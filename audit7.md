> # Audit List 7 (opus-verified actionable subset, 10 findings)
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

2 opus-confirmed NEEDS-WORK findings from audit1.md / section `bridges-hex`.

## Findings

#### F-0042 - BPS/UPS export loads original + current docs simultaneously [fixed: audit7/u-f0042-bps-ups-streaming]

- **Source audit:** audit1.md / `bridges-hex`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** ~7742 (`_export_patches_bps_via_backend`, `_load_source_via_mmap`, `export_patches`)
- **Pattern:** Cat 9
- **Why this is non-functional:** Even the Rust-backed path materialises the entire source document with `_load_source_via_mmap()` returning `bytes(mm)` before handing it to the Rust backend, so the Rust path holds one full file in Python `bytes` (source) while the Python fallback path holds two (source + target). On very large files when the Rust backend lacks `export_patches_bps`/`export_patches_ups`, the Python fallback can OOM. The audit's concern that BPS/UPS export simultaneously materialises both documents is only partially mitigated.
- **Suggested remediation summary:** Stream the source from the on-disk mmap directly to the Rust BPS/UPS encoder (zero-copy via memoryview / buffer protocol), and replace the Python fallback's `bytes(...)` materialisation with chunked streaming that consumes source and target in matched offset windows. The Rust backend signature should accept a length-bounded readable handle so neither side is forced into a full-file `bytes` allocation.
- **Remediation:** Rust gains `HexDocument::export_patches_bps_from_path` and `export_patches_ups_from_path` (in `src/intellicrack-hexcore/src/lib.rs`) which open the source via `memmap2::Mmap` inside Rust and feed the slice directly to `bps_ups::export_bps` / `bps_ups::export_ups`; both methods share a single private `export_patch_from_path_inner` helper. The Python bridge gains `HexEditorBridge._open_source_mmap`, a `contextlib.contextmanager` that yields the source as an `mmap.mmap` view; `_export_patches_bps_via_backend` / `_export_patches_ups_via_backend` prefer the path-based binding and fall through to handing the mmap view to the legacy byte-slice backend via the buffer protocol; `_export_patches_bps_pyfallback` / `_export_patches_ups_pyfallback` now walk the source through that mmap view rather than calling `bytes(mm)`. The BPS / UPS encoder helpers (`_build_bps_patch`, `_build_ups_patch`, and their callees) are typed against a new `_BPSBuffer = bytes | mmap.mmap` alias so the buffer-protocol path is type-correct. `_load_source_via_mmap` is retained as a deprecated compatibility shim. Tests live in `tests/test_audit7/bridges_hex/test_bps_streaming_export.py` and pin: (a) the pyfallback hands `mmap.mmap` to the encoder, not `bytes`; (b) the source-handoff phase against a 2 GiB sparse source keeps tracemalloc peak under 64 MiB; (c) the legacy byte-slice backend path also receives `mmap.mmap`; (d) the new `export_patches_*_from_path` Rust bindings produce valid BPS1 / UPS1 patches that roundtrip.

#### F-0040 - UTF-16 scanner accepts code units like 0x2070 as printable [fixed: audit7/u01-utf16-scanner]

- **Source audit:** audit1.md / `bridges-hex`
- **Reviewer verdict:** UNCLEAR
- **Reviewer assessment:** The line range provided (5050-5071) does not contain UTF-16 scanning code. Lines in that range contain open_process_memory function and VA mapping logic. No UTF-16 scanner found at documented location. The function may have been refactored or removed.

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5050-5071
- **Pattern:** Cat 16


# Findings: providers-meta (from audit2.md)

## Summary

1 opus-confirmed NEEDS-WORK finding from audit2.md / section `providers-meta`.

## Findings

#### F-0021 - `discover_all` records error events but never invalidates the now-known-stale cache entry [fixed: audit7/u02-discover-cache]

- **Source audit:** audit2.md / `providers-meta`
- **Reviewer verdict:** UNCLEAR
- **Reviewer assessment:** Expected exceptions within discover_one are handled with cache invalidation. However, truly unexpected exceptions escaping discover_one (lines 696-698) are logged but don't trigger cache invalidation. This may be acceptable since such exceptions are unplanned failures, but the audit concern of stale-cache-on-error isn't fully addressed for catastrophic failures.

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 437-467
- **Pattern:** Cat 11


# Findings: config-pyproject (from audit4.md)

## Summary

1 opus-confirmed NEEDS-WORK finding from audit4.md / section `config-pyproject`.

## Findings

#### F-0001 - `pyproject.toml` redundantly declares 95+ dev/test/docs/profile packages as runtime `dependencies` [fixed: audit7/u03-runtime-deps]

- **Source audit:** audit4.md / `config-pyproject`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The defect persists. Lines 43-154 list all 95+ development, testing, documentation, and profiling packages in the main `dependencies` array instead of in `optional-dependencies` extras. This causes `pip install intellicrack` to pull pytest, mypy, bandit, sphinx, mkdocs, torch, transformers, and dozens of other non-runtime packages.

- **File:** `pyproject.toml:43-154`
- **Pattern:** Cat 23, Cat 12
- **Why non-factual:** `pip install intellicrack` pulls pytest, mypy, bandit, basedpyright, ruff, sphinx, mkdocs-material, pre-commit, tox, nox, twine, monkeytype, pyannotate, safety, commitizen, bumpversion as runtime requirements. These are development-time tooling packages that have no business in the published distribution's `[project].dependencies` list — they belong in `[dependency-groups]` / `[project.optional-dependencies]` extras (`dev`, `test`, `docs`, `profile`) instead.
- **Suggested remediation summary:** Move every dev/test/docs/profile-only package from `[project].dependencies` into the appropriate `[dependency-groups]` table (`dev`, `test`, `docs`, `profile`) so that `pip install intellicrack` only pulls genuine runtime requirements. Verify against the existing pixi feature/environment layout in `pyproject.toml` to keep tool resolution consistent.


# Findings: sandbox-py (from audit4.md)

## Summary

6 opus-confirmed NEEDS-WORK findings from audit4.md / section `sandbox-py`.

## Findings

#### F-0001 - `SandboxManager.create()` deadlocks on capacity eviction [fixed: audit7/u04-sandbox-deadlock]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The deadlock vulnerability remains unaddressed in current HEAD. Line 287 acquires `self._lock` with `async with self._lock:`, and line 291 calls `await self.destroy(oldest.id)`. The `destroy()` method at line 357 also does `async with self._lock:`, attempting to acquire the same non-reentrant `asyncio.Lock`. This causes indefinite blocking when capacity eviction is triggered. No fix visible in recent commits.

- **File:** `src/intellicrack/sandbox/manager.py`
- **Lines:** 184-192
- **Pattern:** Cat 7
- **Why this is non-functional:** `SandboxManager.create()` acquires `self._lock`. Inside the critical section, when at capacity it calls `await self.destroy(oldest.id)`. `destroy()` also does `async with self._lock:` to take the same lock. `asyncio.Lock` is not reentrant, so the second acquisition blocks indefinitely.

### Category 1 - Empty / Stub Implementations
#### F-0002 - `QEMUSandbox.start()` instantiates `GuestAgentClient` but never calls `connect` [fixed: audit7/u05-qemu-agent-connect]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The fix claimed in commit 1c3bd185 (test suite F-0002) is not actually present in the code. Line 1452 instantiates `GuestAgentClient` but there is no `await self._agent.connect()` call following it. All code paths guarded by `self._agent.is_connected` remain dead. The test at tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py::TestF0002AgentConnectCalled is flawed: it manually calls `fake_agent.connect()` after the test scenario (line 369) rather than verifying that start() itself calls connect().

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1311 + 1949-1994
- **Pattern:** Cat 1
- **Why this is non-functional:** `GuestAgentClient.is_connected` is permanently `False` for the lifetime of the sandbox. Every code path guarded by `self._agent.is_connected` is dead. The "fallback" path in `run_command` writes a script to `<shared>/input/exec_*.cmd` and polls `<shared>/output/result_*.txt`, but nothing in the guest watches the input folder.

#### F-0003 - `_poll_for_result` fallback returns empty stdout/stderr [fixed: audit7/u08-qemu-poll-sidecars]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** ~2490-2525 (`_poll_for_result`); ~2467-2488 (`_generate_execution_script`)
- **Pattern:** Cat 11
- **Why this is non-functional:** When the guest agent is unreachable, `run_command` falls back to a file-polling path: writes a script and watches a result file. The generated execution script only writes the exit code to the result file. `_poll_for_result` returns `(exit_code, "", "")`. Any command run through the fallback path returns meaningless empty stdout and stderr — callers cannot diagnose failures or capture analysis output.
- **Remediation:** `_generate_execution_script` now redirects stdout and stderr to per-invocation sidecar files (`<id>.stdout`, `<id>.stderr`) under the guest's shared `output` folder before writing the exit-code sentinel. `_poll_for_result` now reads both sidecars (via `_read_sidecar`) once the exit-code file appears and returns their content. `_cleanup_result_artifacts` removes the script, result, and sidecar files after a successful read so the shared folder does not accumulate per-invocation artefacts.

### Category 4 - Wrong Field Returned
#### F-0006 - No mechanism to start the guest agent script [fixed: audit7/u06-guest-agent-bootstrap]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** While commit 1c3bd185 claims to fix F-0006 ("agent script startup"), the actual mechanism for launching the guest agent script in the guest remains unclear in the codebase. The agent scripts are written to shared folders but no evidence of actual guest-side execution trigger (e.g., registry runkey, startup batch, or virtualization guest tools integration) is visible. This appears to be a band-aid fix at best: scripts are created but not executed.

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1608-1947
- **Pattern:** Cat 1, Cat 9
- **Why this is non-functional:** `start_agent.cmd` and `start_agent.sh` are written into the shared folder, but nothing in the QEMU launch ever arranges for the guest to execute them.

### Category 4 - Wrong Implementation
#### F-0007 - extract_dropped_files won't work if agent disconnected, allowlist mismatch otherwise [fixed: audit7/u07-extract-dropped-files]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** Commit 1c3bd185 claims to fix F-0007 but the underlying issue persists. Given that F-0002 (agent.connect() not called) remains unfixed, `self._agent.is_connected` is always False, making the agent path permanently dead. The file extraction logic still depends on the broken connection path. Without F-0002 being fixed, F-0007 cannot be truly functional.

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2710-2717
- **Pattern:** Cat 4, Cat 14

### Category 17 - Allowlist / Path Resolution
#### F-0022 - QEMU `apply_anti_evasion` uses bare `reg.exe` blocked by guest agent allowlist [fixed: audit7/u12-qemu-anti-evasion-identity]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** NOT_FIXED
- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** ~3113, 3127, 3141, 3155 (registry dispatches); ~1887-1898 (guest agent allowlist)
- **Pattern:** Cat 17
- **Why this is non-functional:** All four `apply_anti_evasion` invocations called `reg.exe` as a bare command name. The guest agent's `Test-AllowedCommand` only allows entries in `$allowedNames` (`powershell`, `powershell.exe`, `cmd`, `cmd.exe`) or `.exe` files rooted at `Z:\`, `%SystemRoot%\System32\`, or `%SystemRoot%\SysWOW64\`. Bare `reg.exe` failed every check, so the agent returned `exit_code=-1` for all four registry patches and the anti-evasion technique silently did nothing.
- **Resolution:** Replaced every bare `"reg.exe"` dispatch with the absolute `C:\Windows\System32\reg.exe` path stored in the new `WINDOWS_REG_EXE_PATH` module constant. Refactored the registry-command construction into a static helper `_anti_evasion_registry_commands(profile, product_id)` so the dispatch list has a single source of truth. Added regression coverage in `tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py::TestF0022RegExeAllowlistSafe` (four tests) that drive `apply_anti_evasion` against a host-side emulation of `Test-AllowedCommand` and assert every dispatched executable is allowlist-safe.

### Category 21 - Wrong PowerShell Construct
#### F-0029 - QEMU `apply_anti_evasion(profile=...)` ignores profile parameter [fixed: audit7/u08-anti-evasion-profile; identity completion: audit7/u12-qemu-anti-evasion-identity]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The `profile` parameter is accepted and logged in the result dict, but the actual anti-evasion configuration sourced from `self._qemu_config.anti_evasion_profile` (line 2675) at launch time ignores the runtime `profile` parameter. The comment explicitly states "the actual SMBIOS profile is sourced from QEMUConfig.anti_evasion_profile", making the parameter meaningless for controlling runtime behavior.

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2502-2625 (initial fix); SMBIOS vs registry identity drift completed at ~1403-1428 and ~3122/3136
- **Pattern:** Cat 21
- **Identity-drift follow-up:** The initial fix on `audit7/u08-anti-evasion-profile` made SMBIOS profile-aware via `_anti_evasion_smbios_entries`, but `apply_anti_evasion`'s registry writes still hard-coded `"HP"` / `"HP EliteDesk 800 G6"`. With a `workstation` profile the SMBIOS reported Dell while the registry advertised HP, a trivially detectable contradiction. Fixed on `audit7/u12-qemu-anti-evasion-identity` by extracting a single `_anti_evasion_identity(profile) -> tuple[str, str]` helper consumed by both `_anti_evasion_smbios_entries` and `_anti_evasion_registry_commands`, eliminating every hard-coded `"HP"` string outside the helper. Regression coverage in `tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py::TestF0029IdentityProfileConsistency` (parametrised across all three profiles) asserts SMBIOS type-1 manufacturer/product strings and the registry `SystemManufacturer` / `SystemProductName` writes both track the launch-time profile.

### Category 13 - Race Condition / Fixed Sleep
#### F-0031 - QEMU `run_binary` 2-second sleep [fixed: audit7/u09-logs-stable]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** Hardcoded `await asyncio.sleep(2)` after binary execution. Like F-0030, this is a race condition mitigation using sleep instead of proper waiting for monitoring log stabilization.

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2152-2156
- **Pattern:** Cat 13

### Category 4 - Cosmetic, Ineffective
#### F-0013 - `apply_anti_evasion` patches volatile registry hive [fixed: audit7/u11-anti-evasion-wmi-hijack]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** `apply_anti_evasion` writes spoofed manufacturer / product / BIOS strings to `HKLM:\HARDWARE\DESCRIPTION\System\BIOS` and sibling keys. That hive is volatile — rebuilt by the kernel at every boot from PnP enumeration — so the writes vanish before evasive samples can observe them. In any case, malware that queries hardware identity goes through WMI (`Win32_ComputerSystem`, `Win32_ComputerSystemProduct`, `Win32_BIOS`), not the raw hive, so even a persistent write would not reach the evasion check.

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1417-1510
- **Pattern:** Cat 4
- **Why this is non-functional:** Writes target volatile registry data; evasive malware queries WMI providers that are not affected by `HKLM:\HARDWARE\DESCRIPTION` writes.
- **Suggested remediation summary:** Drop every `HKLM:\HARDWARE\DESCRIPTION` write. Generate a MOF file from the active anti-evasion profile that redefines `Win32_ComputerSystem`, `Win32_ComputerSystemProduct`, and `Win32_BIOS` as `[Static]` classes with the spoofed instance values, compile it via `mofcomp.exe -N:root\cimv2 <mof>`, then verify with `Get-CimInstance` that the spoofed values are now returned.

### Category 21 - Targets PPL
#### F-0021 - `dump_memory` cannot succeed against vmwp.exe [fixed: audit7/u11-minidump-target-pid]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The in-guest PowerShell helper calls `MiniDumpWriteDump` with `GetCurrentProcess()`, dumping the PowerShell host that the dispatcher spawned — never the analysis target. A separate host-side fallback tries to open the sandbox worker `vmwp.exe` (a Protected Process Light) which is unreachable from any caller including SYSTEM. Either way the produced minidump describes the wrong process.

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1512-1588 + 1890-1968
- **Pattern:** Cat 21, Cat 4
- **Why this is non-functional:** `MiniDumpWriteDump(GetCurrentProcess(), ...)` captures the PowerShell host instead of the sample under analysis; the resulting dump has none of the binary's state.
- **Suggested remediation summary:** Thread a required `target_pid` argument through `WindowsSandbox.dump_memory` (and the matching `SandboxBridge.memory_dump` surface) into the in-guest PowerShell. Use `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, $targetPid)` and pass that handle to `MiniDumpWriteDump`. Close the handle in `finally`. Reject calls missing or having non-positive `target_pid`.


# Findings: ui-panels-process (from audit4.md)

## Summary

3 opus-confirmed NEEDS-WORK findings from audit4.md / section `ui-panels-process`.

## Findings

#### F-0012 - `ThreadsTab` thread combos only update on explicit Refresh [fixed: audit7/u10-threads-auto-refresh]

- **Source audit:** audit4.md / `ui-panels-process`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The thread combo boxes are only populated when the Refresh button is clicked. New threads created in the target process will not appear until manual refresh. Dynamic thread creation goes unnoticed.

- **File:** `src/intellicrack/ui/panels/process_panel/_threads_tab.py`
- **Lines:** 96-106, 353-384
- **Pattern:** Cat 11


# Findings: sandbox-scripts (from audit3.md)

## Summary

2 opus-confirmed NEEDS-WORK findings from audit3.md / section `sandbox-scripts`.

## Findings

#### F-0019 - `dll_monitor.ps1` payload-name brute force followed by silent `return` loses every event the heuristic misses [fixed: audit7/u11-dll-monitor-unparsed]

- **Source audit:** audit3.md / `sandbox-scripts`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The image-load handler at lines 177-182 previously emitted a `dll_event_unparsed` diagnostic record then silently `return`ed when the payload field set did not match the well-known image-path field list. The event was permanently dropped from the report consumer's view even though the ETW event was real.

- **File:** `src/intellicrack/sandbox/scripts/dll_monitor.ps1`
- **Lines:** 177-182
- **Pattern:** Cat 19
- **Why this is non-functional:** The bridge was lossy: any ETW image-load event from a provider whose payload schema differs from the curated list (`ImageName`, `FileName`, `ImageFileName`) was completely invisible to downstream consumers, so the AI and the user had no way to see that an event occurred or to tune the field list.
- **Suggested remediation summary:** On payload-mismatch, write a structured record to the main monitor log with `image_path` empty plus the observed `payload_schema` and the raw `event_id`. Auto-extend the candidate field name list at runtime from observed events (and from the provider manifest at startup where possible) so subsequent events with the same schema are parsed correctly.

#### F-0025 - `start_monitors.cmd` PowerShell processes spawned with no shutdown coordination [fixed: audit7/u12-monitor-stop-event]

- **Source audit:** audit3.md / `sandbox-scripts`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** Monitor processes spawned by `start_monitors.cmd` had no graceful-stop mechanism. The companion `stop_monitors.cmd` went straight to `taskkill /F /T`, which never invokes each monitor's `finally` clauses, so monitor sessions could not flush a STOP record (or otherwise clean up ETW sessions, WMI subscriptions, and named handles) before being terminated.

- **File:** `src/intellicrack/sandbox/scripts/stop_monitors.cmd`, `src/intellicrack/sandbox/scripts/dll_monitor.ps1`, `src/intellicrack/sandbox/scripts/api_trace.ps1`, `src/intellicrack/sandbox/scripts/injection_monitor.ps1`, `src/intellicrack/sandbox/scripts/kernel_object_monitor.ps1`
- **Lines:** 22-27 (stop_monitors.cmd)
- **Pattern:** Cat 9
- **Why this is non-functional:** `taskkill /F /T` short-circuits each monitor's `finally` cleanup, so STOP telemetry never reaches its lifecycle log, the realtime `TraceEventSession` is leaked, and the WMI subscription leaks into the next sandbox session. The shutdown driver loses every monitor's "I exited cleanly" signal.
- **Suggested remediation summary:** Introduce a named manual-reset event `IntellicrackMonitorStop`. Each of the four monitor PS1s (`dll_monitor`, `api_trace`, `injection_monitor`, `kernel_object_monitor`) opens the event at startup, polls `WaitHandle.WaitOne(0)` non-blocking in its main loop, and breaks out so the `finally` clause runs and writes a STOP record to a per-monitor `*.lifecycle.log`. `stop_monitors.cmd` signals the event via `_stop_monitors_helper.ps1` first, waits up to a configurable grace window (default 10s) per tracked PID, then escalates only the stragglers to `taskkill /F /T`.
# Findings: ui-app-core (from audit5.md)

## Summary

1 verifier-confirmed PARTIAL finding from audit5.md / section `ui-app-core`.

## Findings

### Category 20 - Implemented But Uncalled

#### F-0021 - `ToolOutputPanel.wire_sandbox_backend` reimplemented but no caller anywhere [fixed: audit7/u14-wire-sandbox-backend]

- **Source audit:** audit5.md / `ui-app-core`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/ui/tools.py` (`ToolOutputPanel.wire_sandbox_backend`)
- **Pattern:** Cat 20
- **Why this is non-functional:** The method was a deprecated no-op in the original finding and is now a full implementation (type validation, `SandboxBridge` construction, manager attachment, `register_existing_sandbox`, delegation to `wire_sandbox_bridge`). Grep across the entire `src/` tree finds it defined only in `tools.py` with zero callers. The "implemented" defect is satisfied; the "dead / unreachable" defect is not.
- **Remediation applied:** Added :meth:`MainWindow.wire_sandbox_backend` in `src/intellicrack/ui/app.py` as the public plugin/CLI injection surface that forwards to `ToolOutputPanel.wire_sandbox_backend` and installs the resulting manager on `MainWindow.sandbox_manager`. Added :func:`_wire_preregistered_sandbox` in `src/intellicrack/main.py` which is invoked from `_create_main_window` at startup; it inspects the orchestrator's tool registry for a pre-registered `SandboxBridge` with registered instances and forwards the first one to `MainWindow.wire_sandbox_backend`. Also taught `ToolOutputPanel.get_sandbox_bridge` to surface the deferred bridge before the sandbox panel is constructed so plugin/CLI consumers can reach the wired backend immediately. Regression tests cover the public method, manager reuse, single-invocation forwarding, type validation, the bootstrap helper's wiring path, and its no-op behaviour without pre-registration.
#### F-0022 - `SystemTab` missing `_attached_pid` guards on mitigation/GUI/job-info actions [fixed: audit7/u10-system-tab-pid-guards]

- **Source audit:** audit4.md / `ui-panels-process`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** `_refresh_mitigations`, `_on_gui_resources`, and `_on_job_info` executed without checking `_attached_pid is None`, leading to silent failures or crashes when the operator clicked the corresponding buttons before attaching to a process.

- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Lines:** 700-729, 793-814, 816-837
- **Pattern:** Cat 11
- **Why this is non-functional:** Clicking Query Mitigations / Get GUI Resources / Get Job Info with no attached process produced no visible feedback. The bridge was invoked with `pid=None`, which either silently failed inside the worker thread or raised an exception that was only routed to a `_logger.warning` line — operators had no way to know the action was refused.
- **Suggested remediation summary:** Added a `_require_attached_pid(action)` helper that centralises the guard pattern (structured log, raw-output update, `QMessageBox.warning`) and applied it to every PID-dependent method (`_refresh_privileges`, `_on_enable_debug`, `_refresh_windows`, `_refresh_services`, `_on_read_peb`, `_refresh_mitigations`, `_on_gui_resources`, `_on_job_info`). New regression tests under `tests/ui/test_system_tab_warnings.py` assert that the three previously-unguarded handlers surface a warning dialog and skip dispatch when unattached, and do not raise.

#### F-0023 - `SystemTab` silent `_on_error` paths swallow bridge failures [fixed: audit7/u10-system-tab-show-error]

- **Source audit:** audit4.md / `ui-panels-process`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** Every `_on_error` callback in `SystemTab` invoked `_logger.warning(...)` only. Operators saw no user-visible signal when the bridge call failed, mirroring the silent-failure pattern audit4 already flagged for `ModulesTab`.

- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Lines:** 502-503, 521-522, 553-554, 583-584, 611-612, 638-639, 660-661, 695-696, 720-722, 748-749, 768-769, 788-789, 806-807, 829-830, 857-858
- **Pattern:** Cat 11
- **Why this is non-functional:** Bridge errors from `get_token_privileges`, `adjust_token_privilege`, `get_windows`, `list_services`, `read_peb`, `read_teb`, `pipe_connect`, `pipe_close`, `get_mitigation_policies`, `reg_read_value`, `reg_enum_keys`, `reg_enum_values`, `get_gui_resources`, `get_job_info`, and `query_system_info` were only logged. The operator had no idea their action failed.
- **Suggested remediation summary:** Added a `_show_error(title, exc, log_event=...)` helper that records the structured warning and routes the message through `QMessageBox.warning(parent=self, ...)` with per-action titles. Replaced every `_logger.warning`-only `_on_error` body with a call to the helper (or, for `_on_pipe_close`, an inline equivalent that preserves the `pipe` structured field). New regression tests under `tests/ui/test_system_tab_warnings.py` assert that the three target handlers' error callbacks produce a warning dialog containing the bridge's exception message.
