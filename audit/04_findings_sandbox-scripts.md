> # Workgroup Directive — Execution Order 04/23: `sandbox-scripts`
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
# Findings: sandbox-scripts

## Files audited (8)

- src/intellicrack/sandbox/scripts/api_trace.ps1
- src/intellicrack/sandbox/scripts/clipboard_monitor.ps1
- src/intellicrack/sandbox/scripts/dll_monitor.ps1
- src/intellicrack/sandbox/scripts/injection_monitor.ps1
- src/intellicrack/sandbox/scripts/kernel_object_monitor.ps1
- src/intellicrack/sandbox/scripts/resource_monitor.ps1
- src/intellicrack/sandbox/scripts/service_monitor.ps1
- src/intellicrack/sandbox/scripts/start_monitors.cmd

## Findings

### Category 20 - Dead / Unreachable Code

#### F-0001 - `clipboard_monitor.ps1` fallback polling loop is unreachable

- **File:** `src/intellicrack/sandbox/scripts/clipboard_monitor.ps1`
- **Lines:** 73-85
- **Pattern:** Cat 20
- **Why this is non-functional:** The file-level `$ErrorActionPreference = 'SilentlyContinue'` means most `Add-Type` failures will never throw, so the `catch` (and its polling fallback) is unreachable in practice.

### Category 5 - Swallowed Errors

#### F-0002 - `clipboard_monitor.ps1` blanket `SilentlyContinue` swallows all real errors

- **File:** `src/intellicrack/sandbox/scripts/clipboard_monitor.ps1`
- **Lines:** 1
- **Pattern:** Cat 5

### Category 12 - Configuration Drift

#### F-0003 - `clipboard_monitor.ps1` hardcoded log path conflicts with caller-supplied `-LogDir`

- **File:** `src/intellicrack/sandbox/scripts/clipboard_monitor.ps1`
- **Lines:** 3
- **Pattern:** Cat 12

### Category 16 - Broken Control Flow

#### F-0004 - `clipboard_monitor.ps1` clobbers PowerShell automatic variable `$pid`

- **File:** `src/intellicrack/sandbox/scripts/clipboard_monitor.ps1`
- **Lines:** 93
- **Pattern:** Cat 16
- **Why this is non-functional:** `$pid` is a read-only PowerShell automatic variable. Assigning to it raises `Cannot overwrite variable PID because it is read-only or constant.` Combined with the file-wide `SilentlyContinue`, the handler silently aborts on every clipboard change.

### Category 12 - Configuration Drift (continued)

#### F-0005 - `resource_monitor.ps1` hardcoded `C:\sandbox_shared\logs` ignores caller `-LogDir`

- **File:** `src/intellicrack/sandbox/scripts/resource_monitor.ps1`
- **Lines:** 3
- **Pattern:** Cat 12

#### F-0006 - `resource_monitor.ps1` `SilentlyContinue` hides counter failures forever

- **File:** `src/intellicrack/sandbox/scripts/resource_monitor.ps1`
- **Lines:** 1
- **Pattern:** Cat 5

#### F-0007 - `service_monitor.ps1` hardcoded `C:\sandbox_shared\logs` ignores caller `-LogDir`

- **File:** `src/intellicrack/sandbox/scripts/service_monitor.ps1`
- **Lines:** 3
- **Pattern:** Cat 12

### Category 5 - Error Handling

#### F-0008 - `service_monitor.ps1` blanket `SilentlyContinue` masks registry-read failures

- **File:** `src/intellicrack/sandbox/scripts/service_monitor.ps1`
- **Lines:** 1
- **Pattern:** Cat 5

### Category 7 - Race Conditions

#### F-0009 - `service_monitor.ps1` 2-second polling loop is racy and never compares lifecycle state

- **File:** `src/intellicrack/sandbox/scripts/service_monitor.ps1`
- **Lines:** 21-56
- **Pattern:** Cat 7

### Category 9 - Bridge Integration

#### F-0010 - `start_monitors.cmd` launches monitors fire-and-forget with no PID tracking and no failure surfacing

- **File:** `src/intellicrack/sandbox/scripts/start_monitors.cmd`
- **Lines:** 23
- **Pattern:** Cat 9

### Category 1 - No-Op Exits

#### F-0011 - `api_trace.ps1` `exit 0` on missing dependency masks setup failure as success

- **File:** `src/intellicrack/sandbox/scripts/api_trace.ps1`
- **Lines:** 67-71
- **Pattern:** Cat 1

#### F-0012 - `api_trace.ps1` starts a logman ETL session it never harvests on success path

- **File:** `src/intellicrack/sandbox/scripts/api_trace.ps1`
- **Lines:** 86-106
- **Pattern:** Cat 9

#### F-0013 - `api_trace.ps1` handler relies on payload field names the AuditAPI provider does not expose

- **File:** `src/intellicrack/sandbox/scripts/api_trace.ps1`
- **Lines:** 137-163
- **Pattern:** Cat 16

#### F-0014 - `api_trace.ps1` cleanup mixes managed-session disposal with logman commands targeting the wrong session

- **File:** `src/intellicrack/sandbox/scripts/api_trace.ps1`
- **Lines:** 186-200
- **Pattern:** Cat 24

### Category 20 - Dead Code

#### F-0015 - `injection_monitor.ps1` tracks `$logmanStarted` for a session it never created via logman

- **File:** `src/intellicrack/sandbox/scripts/injection_monitor.ps1`
- **Lines:** 269-285
- **Pattern:** Cat 20

#### F-0016 - `injection_monitor.ps1` `return` from top-level script silently aborts

- **File:** `src/intellicrack/sandbox/scripts/injection_monitor.ps1`
- **Lines:** 51-57
- **Pattern:** Cat 1

### Category 16 - Heuristic Mismatches

#### F-0017 - `injection_monitor.ps1` heuristic mislabels normal thread starts as `shellcode_injection` and fabricates API names

- **File:** `src/intellicrack/sandbox/scripts/injection_monitor.ps1`
- **Lines:** 196-225
- **Pattern:** Cat 16

#### F-0018 - `dll_monitor.ps1` file-mode logman session collides with realtime TraceEventSession on the same name

- **File:** `src/intellicrack/sandbox/scripts/dll_monitor.ps1`
- **Lines:** 73-82
- **Pattern:** Cat 9
- **Why this is non-functional:** ETW does not allow a session to be both file-mode and realtime simultaneously: the second open returns the existing session (no real-time delivery), and `$source.Process()` blocks producing no events.

#### F-0019 - `dll_monitor.ps1` payload-name brute force followed by silent `return` loses every event the heuristic misses

- **File:** `src/intellicrack/sandbox/scripts/dll_monitor.ps1`
- **Lines:** 84-125
- **Pattern:** Cat 19

#### F-0020 - `dll_monitor.ps1` top-level catch falls back to WMI but never reports it, masking degraded mode

- **File:** `src/intellicrack/sandbox/scripts/dll_monitor.ps1`
- **Lines:** 173-186
- **Pattern:** Cat 24

### Category 7 - Race Conditions (continued)

#### F-0021 - `kernel_object_monitor.ps1` 3-second polling loop misses transient kernel objects entirely

- **File:** `src/intellicrack/sandbox/scripts/kernel_object_monitor.ps1`
- **Lines:** 323-341
- **Pattern:** Cat 7

#### F-0022 - `kernel_object_monitor.ps1` `OpenProcess(PROCESS_DUP_HANDLE)` against System processes silently fails

- **File:** `src/intellicrack/sandbox/scripts/kernel_object_monitor.ps1`
- **Lines:** 247-273
- **Pattern:** Cat 5

#### F-0023 - `kernel_object_monitor.ps1` monitor never enables `SeDebugPrivilege` so even peer-process inspection is partial

- **File:** `src/intellicrack/sandbox/scripts/kernel_object_monitor.ps1`
- **Lines:** 226-321
- **Pattern:** Cat 16

### Category 12 - Configuration Drift

#### F-0024 - `start_monitors.cmd` hardcoded default log dir contradicts three monitor scripts

- **File:** `src/intellicrack/sandbox/scripts/start_monitors.cmd`
- **Lines:** 11
- **Pattern:** Cat 12

#### F-0025 - `start_monitors.cmd` PowerShell processes spawned with no shutdown coordination

- **File:** `src/intellicrack/sandbox/scripts/start_monitors.cmd`
- **Lines:** 22-27
- **Pattern:** Cat 9
