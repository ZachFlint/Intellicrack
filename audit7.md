> # Audit List 7 (post-verification actionable subset, 27 findings)
>
> Drive **every F-#### finding below** to production release-ready. For
> each finding: re-verify against the cited source/lines, implement the
> full fix per the `Suggested remediation summary`, and write
> production-grade tests that fail without the fix and pass with it. If a
> finding is already resolved on `main`, annotate it in this file by
> appending `[obsolete: <commit-hash>]` to the F-#### heading line (e.g.
> `#### F-0042 [obsolete: c0bfbdf9] - <original title>`) and move on.
>
> ## Orchestrator Responsibility (Claude)
>
> **Claude bears final, non-delegable responsibility for verifying that
> every fix is a real, root-cause solution — never a workaround,
> monkeypatch, or band-aid that masks the underlying defect.** Reject any
> change that:
>
> - Suppresses, hides, or routes around the failure mode instead of fixing
>   the cause described in `Why this is non-functional`.
> - Adds opt-in flags or "preserve old behavior" toggles that leave the
>   broken code path reachable.
> - Catches and swallows the symptom (logging-only, fake `success: True`,
>   silent fallback, bare `except`) instead of correcting the logic.
> - Replaces one fake-success path with a different fake-success path.
> - Disables, weakens, skips, or `xfail`s tests / assertions to silence a
>   failure.
> - Adds shim layers, polyfills, or compatibility wrappers when the
>   upstream call site or data structure should be corrected directly.
> - Inserts `type: ignore`, `pyright: ignore`, `noqa`, or other
>   suppression directives instead of fixing the actual defect.
> - Hardcodes a value, sentinel, or "known-good" response in place of the
>   real computation.
> - Monkeypatches at runtime or vendors a private copy of upstream code to
>   avoid touching the real broken site.
>
> Do not mark a finding resolved until the underlying defect is
> **actually** gone and the new tests would have caught the original bug.
>
> Hard constraints:
>
> - Production-ready and immediately deployable; zero placeholders, mocks,
>   stubs, simulated implementations, or fake-success returns.
> - `ruff check` clean, fully `basedpyright` compliant, `pydoclint` and
>   `pydocstyle` clean — no inline suppression directives of any kind.
> - Windows-first compatibility, preserve existing functionality, never
>   delete a method binding — implement the missing function instead.
> - Every F-#### below must end fixed-and-tested or annotated
>   `[obsolete: <commit-hash>]` inline on its heading line in this file.
>
> ---


# Findings: bridges-hex (from audit1.md)

## Summary

1 verifier-confirmed PARTIAL finding from audit1.md / section `bridges-hex`.

## Findings

### Category 9 - Memory Inefficiency

#### F-0042 - BPS/UPS export loads original + current docs simultaneously

- **Source audit:** audit1.md / `bridges-hex`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** ~7742 (`_export_patches_bps_via_backend`, `_load_source_via_mmap`, `export_patches`)
- **Pattern:** Cat 9
- **Why this is non-functional:** Even the Rust-backed path materialises the entire source document with `_load_source_via_mmap()` returning `bytes(mm)` before handing it to the Rust backend, so the Rust path holds one full file in Python `bytes` (source) while the Python fallback path holds two (source + target). On very large files when the Rust backend lacks `export_patches_bps`/`export_patches_ups`, the Python fallback can OOM. The audit's concern that BPS/UPS export simultaneously materialises both documents is only partially mitigated.
- **Suggested remediation summary:** Stream the source from the on-disk mmap directly to the Rust BPS/UPS encoder (zero-copy via memoryview / buffer protocol), and replace the Python fallback's `bytes(...)` materialisation with chunked streaming that consumes source and target in matched offset windows. The Rust backend signature should accept a length-bounded readable handle so neither side is forced into a full-file `bytes` allocation.


# Findings: bridges-process (from audit2.md)

## Summary

5 verifier-confirmed PARTIAL findings from audit2.md / section `bridges-process`.

## Findings

### Category 4 - Wrong Implementation

#### F-0008 - `get_seh_chain` WOW64 pointer-size bug

- **Source audit:** audit2.md / `bridges-process`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/process_manager.py`
- **Lines:** ~4963-5010 (`get_seh_chain`)
- **Pattern:** Cat 4
- **Why this is non-functional:** The native-x64 guard correctly raises `ToolError(_ERR_SEH_NOT_APPLICABLE_X64)`. When the target is WOW64 (a 32-bit process on a 64-bit host — the common real-world case), the code falls through and uses `ptr_size = struct.calcsize("P")`. On a 64-bit Python host that returns 8, so the function reads 16-byte SEH records with `<QQ`. WOW64 SEH records are 8 bytes (two 4-byte x86 pointers). Every address and handler returned for a WOW64 target is silently wrong.
- **Suggested remediation summary:** When `_target_is_wow64()` is True, hard-code `ptr_size = 4`, read 8-byte SEH records, and unpack with `<II`. Do not derive `ptr_size` from the host interpreter's pointer width for any path that reads target-process memory.

### Category 4 - Wrong Field Returned

#### F-0019 - `get_handles` tool still returns raw `ObjectTypeIndex` integers

- **Source audit:** audit2.md / `bridges-process`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/process_manager.py`
- **Lines:** ~3396 (`get_handles`), ~3584 (`enum_handles`)
- **Pattern:** Cat 4
- **Why this is non-functional:** A new `enum_handles` method properly resolves type indices to human-readable names via `NtQueryObject(ObjectAllTypesInformation)`, but it is **not registered as a tool**. The tool-callable `process.get_handles` still delegates to `_sync_iterate_handles_for_pid` which returns `"type_index"` as a raw integer. LLM/CLI callers receiving "type_index=37" cannot interpret it. The fix capability exists but isn't wired to the public API surface.
- **Suggested remediation summary:** Either resolve type names inside `get_handles` (call `_build_handle_type_map` once per attachment lifetime and translate each `type_index` to a name string with `type_index` retained as a sibling field), or expose `enum_handles` as the registered tool replacing `get_handles`. Update the tool definition's `returns` description to match.

### Category 7 - Concurrency

#### F-0035 - `search_pattern` blocks the event loop across regions

- **Source audit:** audit2.md / `bridges-process`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/process_manager.py`
- **Lines:** ~2352-2417 (`search_pattern`, `_scan_region_pattern`)
- **Pattern:** Cat 7
- **Why this is non-functional:** Handle enumeration at 100k+ entries was correctly moved to `asyncio.to_thread`, but `search_pattern` still iterates regions synchronously inside the coroutine and calls `_scan_region_pattern` without yielding between regions. Large processes with many readable regions stall the event loop for multi-second intervals, blocking concurrent tool calls and UI updates.
- **Suggested remediation summary:** Dispatch each `_scan_region_pattern` call via `await asyncio.to_thread(...)`, or insert `await asyncio.sleep(0)` between regions. For very large region counts, batch the region list and run each batch in a thread pool so the loop can service other coroutines.

### Category 4 - Wrong Field Returned

#### F-0037 - `query_system_info` returns raw bytes against a "hex string" tool-def contract

- **Source audit:** audit2.md / `bridges-process`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/process_manager.py`
- **Lines:** ~7652-7700 (`query_system_info`), tool definition ~line 1006
- **Pattern:** Cat 4
- **Why this is non-functional:** The function's return type is `bytes` and it returns `buffer.raw[: return_length.value]` (raw bytes). The tool definition advertises `returns="Hex string of raw output buffer"`. Every other hex-returning method in this bridge was corrected; this one was missed. LLM callers serialising the return value into a JSON tool response will hit a non-serialisable `bytes` payload.
- **Suggested remediation summary:** Convert the buffer to a hex string with `buffer.raw[: return_length.value].hex()` before returning. Update the function return type annotation to `str`. Verify the tool-def `returns` text already matches.

### Category 4 - Wrong Implementation

#### F-0044 - `pipe_connect` / `device_open` never insert into the shutdown tracking dicts

- **Source audit:** audit2.md / `bridges-process`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/process_manager.py`
- **Lines:** ~5967-6003 (`pipe_connect`), ~6555-6588 (`device_open`), ~1443-1446 (`shutdown` cleanup loop)
- **Pattern:** Cat 4
- **Why this is non-functional:** `shutdown` iterates `self._pipe_handles` and `self._device_handles` to close them, but neither `pipe_connect` nor `device_open` populates those dicts after successfully opening a handle. The dicts are always empty at shutdown. Section handle tracking (`_section_handles`, `_section_views`) is wired end-to-end correctly, but pipe and device handles leak unless the caller explicitly calls `pipe_close` / `device_close`.
- **Suggested remediation summary:** In `pipe_connect`, after a successful `CreateFileW`, assign `self._pipe_handles[handle] = pipe_name`. In `device_open`, after success, assign `self._device_handles[handle] = device_path`. Ensure `pipe_close` / `device_close` remove the entry after closing.


# Findings: providers-meta (from audit2.md)

## Summary

1 verifier-confirmed PARTIAL finding from audit2.md / section `providers-meta`.

## Findings

### Category 20 - Dead Code

#### F-0023 - `providers/__init__.py` re-exports private TypedDict helpers with no external consumers

- **Source audit:** audit2.md / `providers-meta`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/providers/__init__.py`
- **Lines:** `__all__` declaration
- **Pattern:** Cat 20
- **Why this is non-functional:** `DiscoveryEvent`, `DtypeOption`, and `ModelConfig` are exported via top-level `__all__` even though grep across the codebase shows zero external consumers importing them through the `intellicrack.providers` package surface. `DiscoveryEvent` consumers use `intellicrack.providers.discovery` directly. API-surface bloat persists.
- **Suggested remediation summary:** Remove `DiscoveryEvent`, `DtypeOption`, and `ModelConfig` from `__all__` (and the corresponding `from ... import ...` lines, if present only to satisfy the re-export). Keep them addressable via their original submodules. Confirm no production code or test imports them via `intellicrack.providers.<name>`.


# Findings: bridges-sandbox (from audit2.md)

## Summary

1 verifier-confirmed PARTIAL finding from audit2.md / section `bridges-sandbox`.

## Findings

### Category 5 - State Drift

#### F-0010 - `BridgeState` updated by only 4 methods; `last_error` stays stale across the rest

- **Source audit:** audit2.md / `bridges-sandbox`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/sandbox.py`
- **Lines:** entire bridge class
- **Pattern:** Cat 5
- **Why this is non-functional:** Verifier 2C confirmed `BridgeState` is updated in exactly four methods: `initialize`, `create`, `run_binary`, `execute`. Fifteen-plus other bridge methods (`copy_to`, `copy_from`, `snapshot_create/restore/list/delete`, `pcap_start/stop/stop_pcap`, `screenshot`, `anti_evasion`, `memory_dump`, `extract_dropped_files`, `yara_scan`, and all five analysis methods `extract_iocs`, `timeline`, `detect_behaviors`, `detect_c2`, `diff`) do not touch `BridgeState` at all. `last_error` is never cleared on success in those paths, so GUI / orchestrator consumers reading `bridge.state.last_error` after a successful op may see whatever the previous error was.
- **Suggested remediation summary:** Wrap each public bridge method's success path with `self._state.last_error = None` (or use a shared decorator / context manager that sets `last_error` to the exception text on failure and clears it on success). Update `target_path`, `binary_loaded`, and `target_pid` consistently from every method that changes those fields. Out-of-scope but worth noting: `is_available()` does not check `_manager_destroyed` before re-creating the manager.


# Findings: sandbox-scripts (from audit3.md)

## Summary

2 verifier-confirmed PARTIAL findings from audit3.md / section `sandbox-scripts`.

## Findings

### Category 6 - Silent Data Loss

#### F-0019 - `dll_monitor.ps1` payload-mismatch events dropped from main log

- **Source audit:** audit3.md / `sandbox-scripts`
- **Reviewer verdict:** PARTIAL
- **File:** `scripts/sandbox/dll_monitor.ps1`
- **Lines:** ~177-182
- **Pattern:** Cat 6
- **Why this is non-functional:** Events whose payload layout does not match any of the three candidate field-name lists (`ImageName`, `FileName`, `ImageFileName`) are written to a diagnostic file (`dll_monitor.diag.log`) but then `return` from the action block. The event is still dropped from the main `dll_monitor.log`. The static candidate list isn't auto-extended from payload schema discovery. The silent-drop defect is mitigated (a diagnostic record exists) but not eliminated.
- **Suggested remediation summary:** When no payload field matches the candidate list, write a structured record to the main log with `image_path=null`, `payload_schema=<observed field names>`, and `event_id` so the event is still represented. Optionally extend the candidate list at startup by inspecting the provider manifest's payload schema for the dll-load event.

### Category 7 - Shutdown Race

#### F-0025 - `stop_monitors.cmd` uses `taskkill /F /T` which bypasses PowerShell `finally` blocks

- **Source audit:** audit3.md / `sandbox-scripts`
- **Reviewer verdict:** PARTIAL
- **File:** `scripts/sandbox/stop_monitors.cmd`
- **Lines:** ~50 (`taskkill /PID !TARGET_PID! /F /T`)
- **Pattern:** Cat 7
- **Why this is non-functional:** PID tracking is now correctly implemented in `start_monitors.cmd`, but `stop_monitors.cmd` uses `taskkill /F /T` — a forced hard-kill. PowerShell never gets to execute the `finally` blocks in `api_trace.ps1`, `injection_monitor.ps1`, `dll_monitor.ps1`, `kernel_object_monitor.ps1` that write STOP records and dispose `TraceEventSession` objects. ETW sessions may leak or be orphaned across sandbox runs, leading to "session already exists" errors on the next start.
- **Suggested remediation summary:** Create a named auto-reset event (e.g., `Global\IntellicrackMonitorStop`). Each monitor script polls `WaitHandle::WaitOne(0)` in its main loop and exits via a graceful `break`, then runs `finally`. `stop_monitors.cmd` sets the event and waits up to N seconds for the tracked PIDs to exit before falling back to `taskkill /F` only for processes that didn't honour the event. Alternative: send `CTRL_BREAK_EVENT` to the PS process group with `GenerateConsoleCtrlEvent`.


# Findings: core-analysis (from audit3.md)

## Summary

1 verifier-confirmed PARTIAL finding from audit3.md / section `core-analysis`.

## Findings

### Category 22 - Linter Evasion

#### F-0011 - `_xml_gen` still uses runtime string-construction to evade bandit B405

- **Source audit:** audit3.md / `core-analysis`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/core/script_gen.py` (`_load_etree` helper)
- **Pattern:** Cat 22
- **Why this is non-functional:** The original `importlib.import_module("xml.etree" + "." + "ElementTree")` was replaced with `__import__("xml" + ".etree.ElementTree")` — a different import API using the identical string-split obfuscation pattern. Bandit B405 triggers on the AST pattern `import xml.etree`; both forms evade it by constructing the module name at runtime. CLAUDE.md prohibits suppression by any mechanism including runtime obfuscation.
- **Suggested remediation summary:** Switch the write-side ElementTree usage to `defusedxml.ElementTree` even though the input is internally generated (write-side parsing is still a B405 concern if the file is round-tripped). If `defusedxml` cannot service the API surface required, replace the obfuscation with a clean direct `import xml.etree.ElementTree as ET` and add the bandit exclusion only in the project-wide tool config (`pyproject.toml [tool.bandit]` skips), with an explicit justification comment in that config — not in source. No inline `# noqa` of any kind.


# Findings: sandbox-py (from audit4.md)

## Summary

5 verifier-confirmed findings from audit4.md / section `sandbox-py`: 4 PARTIAL and 1 NOT_FIXED. Anti-evasion is the single most-broken subsystem in the codebase and three of these defects together break sandbox-detection evasion against modern malware.

## Findings

### Category 17 - Allowlist / Path Resolution

#### F-0022 - QEMU `apply_anti_evasion` uses bare `reg.exe` blocked by guest agent allowlist

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** NOT_FIXED
- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 3113, 3127, 3141, 3155; allowlist at ~1887-1898
- **Pattern:** Cat 17
- **Why this is non-functional:** All four `apply_anti_evasion` invocations call `reg.exe` as a bare command name. The guest agent's `Test-AllowedCommand` (~lines 1887-1898) only allows entries in `allowedNames` (`powershell`, `powershell.exe`, `cmd`, `cmd.exe`) or `.exe` files rooted at `Z:\`, `%SystemRoot%\System32\`, or `%SystemRoot%\SysWOW64\`. `"reg.exe"` fails every check; the agent returns `exit_code=-1` for all four registry patches and the anti-evasion technique silently does nothing.
- **Suggested remediation summary:** Use the full System32 path: pass `"$env:SystemRoot\System32\reg.exe"` (or literal `"C:\Windows\System32\reg.exe"`) as the executable for every `reg.exe` invocation in `apply_anti_evasion`. Add an integration test that asserts `Test-AllowedCommand` returns `$true` for the resolved path. This defect must be fixed together with F-0029 — even after this fix the registry writes will still advertise a different vendor than SMBIOS.

### Category 3 - Wrong Registry Hive

#### F-0013 - `apply_anti_evasion` patches volatile `HARDWARE\DESCRIPTION` hive

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** ~1538-1546
- **Pattern:** Cat 3
- **Why this is non-functional:** Writes `SystemManufacturer`, `SystemProductName`, `BIOSVendor`, `BIOSVersion` to `HKLM:\HARDWARE\DESCRIPTION\System\BIOS`. That hive is volatile and rebuilt by the HAL during next hardware enumeration. WMI queries (`Win32_ComputerSystem`, `Win32_ComputerSystemProduct`) read live hardware data, not these keys. Sandbox-detecting malware querying WMI still sees the real fingerprint. The two additional keys (`Disk\Enum`, `SystemInformation`) are writable but the BIOS keys are the ones malware actually inspects.
- **Suggested remediation summary:** Replace the volatile hive writes with one of: (a) hypervisor-level SMBIOS override at QEMU launch (already implemented elsewhere for QEMU sandbox), (b) WMI provider hijack via `ROOT\CIMV2:Win32_ComputerSystemProduct` instance override using a WMI MOF file, or (c) kernel-mode hook of `NtQuerySystemInformation`. For the Windows-sandbox path which has no hypervisor, prefer the WMI provider hijack approach. Drop the `HARDWARE\DESCRIPTION` writes entirely once an effective alternative is in place.

### Category 4 - Wrong Process

#### F-0021 - `dump_memory` MiniDump targets PowerShell itself, not the analyzed binary

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** ~1651-1653
- **Pattern:** Cat 4
- **Why this is non-functional:** The guest-side script calls `[MiniDumper]::GetCurrentProcess()` and `[MiniDumper]::GetCurrentProcessId()`. Those Win32 APIs always return the calling process's handle/PID — which is the PowerShell interpreter running the script. The binary under analysis is never referenced. The resulting dump contains no useful data about the analyzed target's runtime state. `_minidump_via_procdump` exists but is never called.
- **Suggested remediation summary:** In the guest-side script, accept the target PID (or target image name) as a parameter. Resolve to a process handle via `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, $targetPid)`. Pass that handle (not `GetCurrentProcess()`) and `$targetPid` (not `GetCurrentProcessId()`) to `MiniDumpWriteDump`. The host-side caller must already know the target PID since it launched the binary; thread it through.

### Category 21 - Profile Parameter Drift

#### F-0029 - QEMU `apply_anti_evasion` SMBIOS profile-aware but registry hardcoded "HP"

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 3102 (SMBIOS derives from profile), 3122 + 3136 (registry hardcoded HP)
- **Pattern:** Cat 21
- **Why this is non-functional:** `_anti_evasion_smbios_entries` correctly switches manufacturer/product strings on profile (`workstation` → Dell/OptiPlex, `laptop` → Lenovo/ThinkPad, `default` → HP/EliteDesk). Lines 3122 and 3136 unconditionally write `"HP"` and `"HP EliteDesk 800 G6"` to the registry regardless of profile. When `workstation` is requested, SMBIOS reports Dell while the registry (if F-0022's allowlist bug were fixed) would say HP — a trivially detectable contradiction.
- **Suggested remediation summary:** Extract the per-profile vendor/product mapping to a single function (e.g., `_anti_evasion_identity(profile) -> tuple[str, str]`) used by both `_anti_evasion_smbios_entries` and the registry writes. Use the resolved tuple consistently. Must be fixed alongside F-0022 — otherwise the registry path remains dead.

### Category 11 - Fallback Path Incompleteness

#### F-0003 - `_poll_for_result` fallback returns empty stdout/stderr

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** ~2490-2525 (`_poll_for_result`); ~2467-2488 (`_generate_execution_script`)
- **Pattern:** Cat 11
- **Why this is non-functional:** When the guest agent is unreachable, `run_command` falls back to a file-polling path: writes a script and watches a result file. The generated execution script writes only the exit code to the result file. `_poll_for_result` returns `(exit_code, "", "")`. Any command run through the fallback path returns meaningless empty stdout and stderr — callers cannot diagnose failures or capture analysis output.
- **Suggested remediation summary:** In `_generate_execution_script`, redirect stdout and stderr to two sidecar files alongside the result file (`<id>.stdout`, `<id>.stderr`) using PowerShell's `*>>` operator or explicit `[System.IO.File]::WriteAllText`. In `_poll_for_result`, after the result file lands, read both sidecar files (returning empty string only if the file truly does not exist) and return `(exit_code, stdout, stderr)`.


# Findings: ui-panels-process (from audit4.md)

## Summary

2 verifier-discovered PARTIAL findings from audit4.md / section `ui-panels-process` — both were stamped FIXED in the first round and downgraded by the verifier with file:line evidence.

## Findings

### Category 4 - Missing None Guard

#### F-0022 - SystemTab methods still pass `_attached_pid` to bridge without `is None` check

- **Source audit:** audit4.md / `ui-panels-process` (verifier dispute)
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Lines:** ~725 (`_refresh_mitigations`), ~810 (`_on_gui_resources`), ~833 (`_on_job_info`)
- **Pattern:** Cat 4
- **Why this is non-functional:** The four methods explicitly named in the original F-0022 (`_refresh_privileges`, `_on_enable_debug`, `_refresh_services`, `_on_read_peb`) all received the `_attached_pid is None` guard. The verifier found three additional methods in the same class with the identical defect uncorrected: `_refresh_mitigations`, `_on_gui_resources`, `_on_job_info` all pass `self._attached_pid` directly to the bridge with no None check. The original audit's class-level concern ("operates on Intellicrack's own process when nothing is attached") is still reachable through those three buttons.
- **Suggested remediation summary:** Add the same guard pattern used in the four originally-fixed methods to `_refresh_mitigations`, `_on_gui_resources`, and `_on_job_info`. Prefer factoring the guard into a private helper (`_require_attached_pid` → `int | None`) that returns the PID or shows the "not attached" status message and returns None, so future SystemTab methods cannot miss the guard.

### Category 5 - Silent Error Consumption

#### F-0023 - SystemTab errors logged but not surfaced to user

- **Source audit:** audit4.md / `ui-panels-process` (verifier dispute)
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Pattern:** Cat 5
- **Why this is non-functional:** Every user-triggered SystemTab action (Query Privileges, Enable Debug Privilege, Enumerate Windows, Enumerate Services, Read PEB, Read TEB, Connect Pipe, Query Mitigations, all registry operations, GUI Resources, Job Info, Raw Query) has an `_on_error` callback that calls `_logger.warning` and nothing else. The user sees no indication of failure. `ModulesTab` (correctly FIXED as F-0024) uses `QMessageBox.warning` for the equivalent error paths. Logging to a structlog sink the user never sees does not satisfy the original Cat-5 "silent error consumption" criterion for user-facing operations.
- **Suggested remediation summary:** Replace each `_on_error` callback in SystemTab with a call to a shared helper that both logs at warning level and shows a `QMessageBox.warning` (parent=self) containing the user-friendly error message. Mirror the pattern already established in `ModulesTab`. Each action needs its own message text; do not fold them into a single generic dialog.


# Findings: ui-panels-hex (from audit4.md)

## Summary

2 verifier-confirmed PARTIAL findings from audit4.md / section `ui-panels-hex`.

## Findings

### Category 5 - Missing State Notification

#### F-0012 - `_templates._on_apply_template` does not emit `notify_template_registered` [fixed: audit7/u11-hex-template-notif]

- **Source audit:** audit4.md / `ui-panels-hex`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/ui/panels/hex_editor/_templates.py`
- **Lines:** ~160-164 (`_on_apply_template`); helper at line 65, used correctly in `_on_import_template` line 306
- **Pattern:** Cat 5
- **Why this is non-functional:** `_on_apply_template` calls `_notify_state_pattern_executed` but never `_notify_state_template_registered`. The helper exists on the class. AI tools / CLI consumers calling `hex_editor.list_templates` after a GUI apply via the templates mixin will receive stale state — the newly-applied template is invisible until the next bridge re-sync.
- **Suggested remediation summary:** Add `self._notify_state_template_registered(template_name, ...)` to the success branch of `_on_apply_template`, mirroring what `_on_import_template` already does. Confirm the template name and pattern body are the same values passed to the bridge.

#### F-0017 - `_pattern_editor._apply_via_interpreter` does not emit `notify_template_registered` [fixed: audit7/u11-hex-template-notif]

- **Source audit:** audit4.md / `ui-panels-hex`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/ui/panels/hex_editor/_pattern_editor.py`
- **Lines:** ~344-351 (`_apply_via_interpreter`); contrast with `_on_pattern_apply` lines 288-298
- **Pattern:** Cat 5
- **Why this is non-functional:** The non-interpreter path in `_on_pattern_apply` emits both `notify_template_registered` and `notify_pattern_executed`. The interpreter fast-path `_apply_via_interpreter` only emits `notify_pattern_executed`. When the HexPat interpreter is available (`hexpat_interpreter_available` is True), DSL execution that produces a named template will not inform the state holder of the new template registration.
- **Suggested remediation summary:** Add `self.state_holder.notify_template_registered(template_name, ...)` (or `_notify_state_template_registered` if that helper exists on this mixin) inside `_apply_via_interpreter`'s success branch, mirroring the non-interpreter path. Resolve the template name from the same source the non-interpreter path uses.


# Findings: core-hexpat (from audit5.md)

## Summary

1 verifier-downgraded PARTIAL finding from audit5.md / section `core-hexpat` — first round stamped FIXED, verifier discovered the GUI integration is missing.

## Findings

### Category 1 - Implemented But Unwired

#### F-0007 - Print sink wired through interpreter but production callers never pass one

- **Source audit:** audit5.md / `core-hexpat` (verifier dispute)
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/core/hexpat/interpreter.py` (sink mechanism), call sites in `src/intellicrack/ui/panels/hex_editor/_pattern_editor.py:313` and `src/intellicrack/bridges/hex_editor.py:2378`
- **Pattern:** Cat 1
- **Why this is non-functional:** `_wire_stdlib_to_evaluator` correctly calls `set_print_sink(self._print_sink)` at `interpreter.py:284`, so the wiring through to `_io_print` is real. But both production call sites instantiate the interpreter with no `print_sink=` argument: `HexPatInterpreter_cls()` at `_pattern_editor.py:313` and `_HexPatInterpreter()` at `bridges/hex_editor.py:2378`. `self._print_sink` defaults to `None`, so on each `execute()` the call becomes `set_print_sink(None)` which clears any sink. `_io_print` then logs only to structlog — invisible to the user in the hex-editor panel. The infrastructure works but the GUI integration is absent.
- **Suggested remediation summary:** In `_pattern_editor.py`, pass `print_sink=self._append_to_pattern_output` (or equivalent UI append callback that writes to the pattern panel's output widget) when constructing the interpreter. In `bridges/hex_editor.py:2378`, accept and forward a sink callback so the AI / CLI caller can see `print()` output via the bridge's response payload. Add a regression test that asserts `print("X")` inside a pattern lands in the GUI widget (or the bridge response).


# Findings: ui-app-core (from audit5.md)

## Summary

2 verifier-confirmed PARTIAL findings from audit5.md / section `ui-app-core`.

## Findings

### Category 11 - Wasted Computation

#### F-0007 - "Tool Status..." discards pre-fetched statuses

- **Source audit:** audit5.md / `ui-app-core`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/ui/app.py` (`_on_tool_status`, `_refresh_tool_status`); `src/intellicrack/ui/dialogs/tool_status.py` (`ToolStatusDialog.__init__`)
- **Lines:** `ToolStatusDialog._refresh_status` ~line 1389
- **Pattern:** Cat 11
- **Why this is non-functional:** `_on_tool_status` calls `_refresh_tool_status()`, logs `len(tool_statuses)`, then discards the returned dict. `ToolStatusDialog.__init__` accepts only `tool_registry=` — no `tool_statuses` parameter. The dialog's own `_refresh_status()` launches independent `ToolStatusCheckWorker` threads regardless. Every "Tool Status..." click does two redundant rounds of tool-checking.
- **Suggested remediation summary:** Either (a) add `tool_statuses: dict | None = None` to `ToolStatusDialog.__init__`, store on the instance, and skip the initial worker launch when pre-fetched data is present (re-fetch only on explicit user refresh); or (b) drop the `_refresh_tool_status()` call from `_on_tool_status()` entirely since the dialog already manages its own status workers. Option (a) is preferable because it makes the dialog open faster.

### Category 20 - Implemented But Uncalled

#### F-0021 - `ToolOutputPanel.wire_sandbox_backend` reimplemented but no caller anywhere

- **Source audit:** audit5.md / `ui-app-core`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/ui/widgets/tools.py` (`ToolOutputPanel.wire_sandbox_backend`)
- **Pattern:** Cat 20
- **Why this is non-functional:** The method was a deprecated no-op in the original finding and is now a full implementation (type validation, `SandboxBridge` construction, manager attachment, `register_existing_sandbox`, delegation to `wire_sandbox_bridge`). Grep across the entire `src/` tree finds it defined only in `tools.py` with zero callers. The "implemented" defect is satisfied; the "dead / unreachable" defect is not.
- **Suggested remediation summary:** Either (a) add at least one real call site that exercises this code path under a production scenario — for example, call it from `MainWindow` when an externally-supplied sandbox instance is injected via plugin or CLI; or (b) if no such injection path is actually planned, remove the method binding entirely. CLAUDE.md forbids deleting method bindings without a functional replacement, so option (a) is preferred. If removed, document why in a commit message.


# Findings: bridges-x64dbg (from audit6.md)

## Summary

1 verifier-confirmed PARTIAL finding from audit6.md / section `bridges-x64dbg`.

## Findings

### Category 2 - Hardcoded Return Values & Fake Success

#### F-0001 - 19 fire-and-forget wrappers return unverified `{"success": True}`

- **Source audit:** audit6.md / `bridges-x64dbg`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/x64dbg_bridge.py`
- **Pattern:** Cat 2
- **Why this is non-functional:** The high-impact wrappers (`run_to`, `patch_instruction`, `nop_range`, `set_breakpoint`) now do real post-condition verification. The verifier confirmed 19 wrappers still return unconditional `{"success": True}` after only confirming the command was queued: `set_label`, `set_comment`, `enable_breakpoint`, `disable_breakpoint`, `suspend_thread`, `resume_thread`, `switch_thread`, `set_thread_name`, `trace_into`, `trace_over`, `step_count`, `animate_start`, `animate_stop`, `script_load`, `script_run`, `script_cmd`, `script_abort`, `plugin_load`, `plugin_unload`. All route through `_send_command` → `_send_pipe_command("exec", ...)` — x64dbg's script engine confirms the command parsed, not that it took effect.
- **Suggested remediation summary:** For each of the 19 named wrappers, add a verification step appropriate to the operation:
  - `set_label` / `set_comment`: readback via the corresponding `get_*` plugin command; compare.
  - `enable_breakpoint` / `disable_breakpoint`: query `bpdlist` / `bphlist` and confirm the target's enabled flag matches the requested state.
  - `suspend_thread` / `resume_thread` / `switch_thread` / `set_thread_name`: query `thread_list` or the focused thread state and confirm the post-condition.
  - `trace_into` / `trace_over` / `step_count`: poll `is_running` and the instruction pointer until the step completes or a timeout fires; raise `ToolError` on timeout.
  - `animate_start` / `animate_stop`: query the animation state.
  - `script_load` / `script_run` / `script_cmd` / `script_abort`: read the script error register / last-error pipe; raise on non-empty error.
  - `plugin_load` / `plugin_unload`: query the plugin list and confirm presence/absence.
  Each wrapper must raise `ToolError` on verification failure; do not return `{"success": False}`. Note: F-0016 (INFO logging for these wrappers) was resolved — the verifier confirmed all 19 already use `_logger.debug("x64dbg_command_queued", ...)`.


# Findings: core-orchestration (from audit6.md)

## Summary

3 verifier-confirmed PARTIAL findings from audit6.md / section `core-orchestration`. F-0022 was verifier-downgraded from FIXED.

## Findings

### Category 20 - Implemented But Uncalled

#### F-0007 - `Session.set_tool_state` works but no bridge calls it

- **Source audit:** audit6.md / `core-orchestration`
- **Reviewer verdict:** PARTIAL
- **File:** Definitions in `src/intellicrack/core/session.py`; consumers should be in `src/intellicrack/bridges/*`
- **Pattern:** Cat 20
- **Why this is non-functional:** `Session.set_tool_state` and `Session.clear_tool_state` are correctly implemented and serialised. Grep across `src/intellicrack/` shows no bridge implementation invokes them on production code paths. `tool_states` persists as `{}` on every save. The feature is dead at runtime.
- **Suggested remediation summary:** In each bridge (`FridaBridge`, `GhidraBridge`, `X64DbgBridge`, `CutterBridge`, `SandboxBridge`, `HexEditorBridge`, `ProcessManagerBridge`), call `self._session.set_tool_state(ToolState(...))` on connect/attach/error/detach events. Pass the active `Session` reference to each bridge during orchestrator wire-up. The `ToolState` payload should capture: connected state, target identifier (PID / path / sandbox instance ID), last error string, last action timestamp. Add `clear_tool_state` on detach. Add a regression test that loads a saved session and observes non-empty `tool_states`.

#### F-0008 - `Session.add_tag` works but no UI / orchestrator entry point

- **Source audit:** audit6.md / `core-orchestration`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/core/session.py`; UI consumers should be in `src/intellicrack/ui/dialogs/session_manager.py` and orchestrator
- **Pattern:** Cat 20
- **Why this is non-functional:** `Session.add_tag` / `Session.remove_tag` and the `session_tags` DB table are implemented and work correctly when invoked. No UI surface, no orchestrator API method, and no bridge invokes `add_tag` on production paths. Tags can only be set by direct test code.
- **Suggested remediation summary:** Add tag management UI to `SessionManagerDialog`: a tag chips widget displaying current tags with click-to-remove, plus an "Add tag..." input. Wire the dialog to call `session.add_tag` / `session.remove_tag` and emit a signal so the orchestrator updates its active-session view. Optionally expose an `orchestrator.tag_current_session(tag: str)` API for CLI / scripting callers. Regression test: create a session, set two tags via the dialog interaction, save and reload, confirm tags survive the round-trip.

### Category 1 - Protocol Body

#### F-0022 - `CompiledYaraRules.match` Protocol body still returns concrete `[]`

- **Source audit:** audit6.md / `core-orchestration` (verifier dispute)
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/core/types.py`
- **Lines:** ~141 (`CompiledYaraRules.match`)
- **Pattern:** Cat 1
- **Why this is non-functional:** `HexDocumentLike` (lines 28-49) and `HexDocumentFull` (lines 53-118) were correctly converted to use `...  # protocol body`. `CompiledYaraRules.match` at line 141 still contains `_ = (self, data, filepath, timeout); return []` — the exact anti-pattern the original finding called out. The first round's justification that `@runtime_checkable` `isinstance` checks require a concrete return is incorrect: `isinstance` against `@runtime_checkable` Protocols verifies method presence only, not return values.
- **Suggested remediation summary:** Replace `_ = (self, data, filepath, timeout); return []` with `...  # protocol body` in `CompiledYaraRules.match`. Confirm `@runtime_checkable isinstance` checks elsewhere still work (they will — they inspect method presence via `hasattr`). If `basedpyright` complains about the unused parameters, parameter names are already self-documenting via the signature; no additional change should be needed.
