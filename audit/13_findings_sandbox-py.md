> # Workgroup Directive — Execution Order 13/23: `sandbox-py`
>
> Spawn a multi-agent workgroup to drive **every F-#### finding below** to
> production release-ready. The workgroup must run this pipeline for every
> finding in this file:
>
> 1. **`developer`** agents (in parallel where findings touch disjoint
>    files) — implement the full fix per the finding's `Suggested
>    remediation summary`. No placeholders, mocks, stubs, hardcoded
>    returns, or fake-success paths. Re-verify each finding against the
>    cited source/lines before fixing; if already resolved, annotate
>    `[obsolete]` with the resolving commit hash and move on.
> 2. **`code-reviewer`** — verify each fix actually addresses the failure
>    mode described in `Why this is non-functional` and audit every caller
>    listed under `Callers / blast radius` for regressions.
> 3. **`test-writer`** — author production-grade tests that fail without
>    the fix and pass with it. Tests must execute against real binaries,
>    real bridges, and real protocols. No mocks of the unit under test.
> 4. **`test-reviewer`** — confirm tests genuinely validate the fix and
>    meet Intellicrack's no-mock standard.
> 5. **`linter`** — run `ruff check`, `basedpyright`, `pydoclint`, and
>    `pydocstyle`; resolve every finding without suppression directives.
>
> Hard constraints (non-negotiable):
>
> - Production-ready and immediately deployable; zero placeholders, mocks,
>   stubs, simulated implementations, or fake-success returns.
> - `ruff check` clean, fully `basedpyright` compliant, `pydoclint` and
>   `pydocstyle` clean — no inline suppression directives of any kind.
> - Windows-first compatibility, preserve existing functionality, never
>   delete a method binding — implement the missing function instead.
> - When this file is fully processed, every F-#### below must be either
>   fixed-and-tested or annotated `[obsolete]` with the resolving commit.
> - **All work for this file ships as one single PR (one PR per prompt /
>   per file).** Every F-#### in this file must be batched into the same
>   PR — do not split findings across multiple PRs, and do not merge any
>   subset until the whole file is fixed-and-tested or annotated
>   `[obsolete]`.
>
> ---
>
# Findings: sandbox-py

## Files audited (8)

- src/intellicrack/sandbox/**init**.py
- src/intellicrack/sandbox/_log_helpers.py
- src/intellicrack/sandbox/_log_parsers.py
- src/intellicrack/sandbox/analysis.py
- src/intellicrack/sandbox/base.py
- src/intellicrack/sandbox/manager.py
- src/intellicrack/sandbox/qemu.py
- src/intellicrack/sandbox/windows.py

## Findings

### Category 7 - Concurrency Issues

#### F-0001 - `SandboxManager.create()` deadlocks on capacity eviction

- **File:** `src/intellicrack/sandbox/manager.py`
- **Lines:** 184-192
- **Pattern:** Cat 7
- **Why this is non-functional:** `SandboxManager.create()` acquires `self._lock`. Inside the critical section, when at capacity it calls `await self.destroy(oldest.id)`. `destroy()` also does `async with self._lock:` to take the same lock. `asyncio.Lock` is not reentrant, so the second acquisition blocks indefinitely.

### Category 1 - Empty / Stub Implementations

#### F-0002 - `QEMUSandbox.start()` instantiates `GuestAgentClient` but never calls `connect`

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1311 + 1949-1994
- **Pattern:** Cat 1
- **Why this is non-functional:** `GuestAgentClient.is_connected` is permanently `False` for the lifetime of the sandbox. Every code path guarded by `self._agent.is_connected` is dead. The "fallback" path in `run_command` writes a script to `<shared>/input/exec_*.cmd` and polls `<shared>/output/result_*.txt`, but nothing in the guest watches the input folder.

### Category 4 - Wrong Field Returned

#### F-0003 - `_poll_for_result` returns hardcoded empty stdout/stderr

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2042-2076
- **Pattern:** Cat 4

### Category 15 - Windows Compatibility

#### F-0004 - `-cpu host` requires hardware virtualisation; broken with TCG fallback

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1119-1132
- **Pattern:** Cat 15, Cat 21

#### F-0005 - SMB shared folder unavailable on Windows-host QEMU; 9p unsupported

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1158-1170
- **Pattern:** Cat 15

### Category 1 - Empty / Stub

#### F-0006 - No mechanism to start the guest agent script

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1608-1947
- **Pattern:** Cat 1, Cat 9
- **Why this is non-functional:** `start_agent.cmd` and `start_agent.sh` are written into the shared folder, but nothing in the QEMU launch ever arranges for the guest to execute them.

### Category 4 - Wrong Implementation

#### F-0007 - extract_dropped_files won't work if agent disconnected, allowlist mismatch otherwise

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2710-2717
- **Pattern:** Cat 4, Cat 14

### Category 21 - Wrong PowerShell Construct

#### F-0008 - `_file_monitor_source` uses `$using:` which is invalid in `Register-ObjectEvent -Action`

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 862-877
- **Pattern:** Cat 21
- **Why this is non-functional:** `$using:logPath` is only valid in `Invoke-Command`, `ForEach-Object -Parallel`, or other runspace-bound script blocks. The action terminates immediately and never writes to `file_monitor.log`.

#### F-0009 - QEMU agent script same `$using:` defect

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1457-1468
- **Pattern:** Cat 21

### Category 13 - Heuristic Mismatch

#### F-0010 - `_resolve_worker_pid` heuristic doesn't match docstring

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 469-533
- **Pattern:** Cat 13, Cat 21

### Category 21 - Wrong Attribute Name

#### F-0011 - `time_limit` vs `timeout_seconds` mismatch

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 132-149
- **Pattern:** Cat 21

### Category 4 - Wrong Format / Return Contract

#### F-0012 - `pktmon` writes ETL not PCAP

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1295-1363
- **Pattern:** Cat 4

### Category 4 - Cosmetic, Ineffective

#### F-0013 - `apply_anti_evasion` patches volatile registry hive

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1417-1510
- **Pattern:** Cat 4

### Category 18 - Resource Leak

#### F-0014 - `_cleanup` shutil.rmtree silently swallows errors

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 535-550
- **Pattern:** Cat 18, Cat 6

### Category 11 - Redundant Work / Side Effects

#### F-0015 - `start()` redoes accelerator detection

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1226-1322
- **Pattern:** Cat 11, Cat 14

### Category 21 - Wrong Success Condition

#### F-0016 - `_detect_accelerator` reports WHPX available on Hyper-V-disabled hosts

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 944-995
- **Pattern:** Cat 21

### Category 14 - Silent Error Swallowing

#### F-0017 - `_dispatcher_ps1_source` catch swallows all errors

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 685-734
- **Pattern:** Cat 14

### Category 21 - Fragile PowerShell

#### F-0018 - `_process_monitor_source` uses `$pid` automatic variable

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1011-1049
- **Pattern:** Cat 21

#### F-0019 - `_registry_monitor_source` hardcoded REG_SZ + unapproved verb

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 883-954
- **Pattern:** Cat 4, Cat 21

### Category 4 - Effectively No-Op

#### F-0020 - `extract_dropped_files` ignores xcopy exit codes

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1627-1688
- **Pattern:** Cat 4, Cat 18

### Category 21 - Targets PPL

#### F-0021 - `dump_memory` cannot succeed against vmwp.exe

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1512-1588 + 1890-1968
- **Pattern:** Cat 21, Cat 4

### Category 21 - Allowlist Mismatch

#### F-0022 - QEMU `apply_anti_evasion` uses `reg.exe` blocked by guest agent allowlist

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2536-2620
- **Pattern:** Cat 21

### Category 4 - Wrong Parser

#### F-0023 - `list_snapshots` parses QMP response incorrectly

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2298-2318
- **Pattern:** Cat 4

### Category 18 - Resource Leak

#### F-0024 - `get_available_types` triggers expensive subprocesses on every call

- **File:** `src/intellicrack/sandbox/manager.py`
- **Lines:** 130-146
- **Pattern:** Cat 18

#### F-0025 - `stop` does not clean active captures

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 820-822 + 1324-1364
- **Pattern:** Cat 18

### Category 4 - Over-Broad Pattern

#### F-0026 - `_DOMAIN_PATTERN` matches `.dll`, `.exe`, etc

- **File:** `src/intellicrack/sandbox/analysis.py`
- **Lines:** 38-41
- **Pattern:** Cat 4, Cat 23

### Category 4 - Wrong Source Set

#### F-0027 - `yara_scan` falls back to scanning user input

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1693-1780
- **Pattern:** Cat 4

#### F-0028 - QEMU `yara_scan` same defect

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2810-2828
- **Pattern:** Cat 4

### Category 21 - Profile Selected But Ignored

#### F-0029 - QEMU `apply_anti_evasion(profile=...)` ignores profile parameter

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2502-2625
- **Pattern:** Cat 21

### Category 13 - Race Condition / Fixed Sleep

#### F-0030 - Windows `run_binary` 3-second sleep

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1191-1232
- **Pattern:** Cat 13

#### F-0031 - QEMU `run_binary` 2-second sleep

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2152-2156
- **Pattern:** Cat 13

### Category 11 - Spawns Subprocess Every Call

#### F-0032 - `WindowsSandbox.is_available` invokes Get-WindowsOptionalFeature on every call

- **File:** `src/intellicrack/sandbox/manager.py`
- **Lines:** 130-146
- **Pattern:** Cat 11

### Category 18 - Disk Leak

#### F-0033 - `run_command` ticket files never deleted

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1083-1105
- **Pattern:** Cat 18

### Category 4 - Wrong Result Label

#### F-0034 - Windows `run_binary` always reports "success" regardless of exit_code

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1107-1195
- **Pattern:** Cat 4

#### F-0035 - QEMU `run_binary` same defect

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2078-2174
- **Pattern:** Cat 4
