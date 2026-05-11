> # Audit List 3/6
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

# Findings: bridges-installer

## Files audited (2)

- src/intellicrack/bridges/installer.py
- src/intellicrack/bridges/named_pipe_client.py

## Findings

### Category 2 - Hardcoded Return Values & Fake Success

#### F-0001 - PROCESS tool returns sentinel "builtin" path with no real validation [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 257-261, 452-453, 497-498
- **Pattern:** Cat 2, "Return literal sentinels treated as success"
- **Excerpt:**

  ```python
  if tool == ToolName.PROCESS:
      return Path("builtin")
  ...
  if tool == ToolName.PROCESS:
      return True
  ...
  if tool == ToolName.PROCESS:
      return InstallResult(success=True, path=Path("builtin"))
  ```

- **Why this is non-functional:** `find_tool`, `verify_tool`, and `install_tool` short-circuit for `ToolName.PROCESS` and report success without checking anything. `Path("builtin")` is a literal string that resolves to a non-existent relative directory. Downstream callers that treat the returned `Path` as real filesystem state (e.g. `path.is_file()`, `path / "process.exe"`) will silently get incorrect behavior. Even if the conceit is "process control is built-in", the contract should not be expressed as a fake `Path`.
- **Callers / blast radius:** `src/intellicrack/bridges/installer.py:498`; `src/intellicrack/ui/app.py:957` via `get_all_tool_status`.
- **Suggested remediation summary:** Use a proper sentinel type or a separate `installed: bool` flag.

#### F-0002 - Frida "path" is the literal string "frida-python" [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 312-316, 459-460, 564-568
- **Pattern:** Cat 2, "Hardcoded sentinel masquerading as a real value"
- **Excerpt:**

  ```python
  return Path("frida-python")
  ...
  if tool == ToolName.FRIDA:
      return path == Path("frida-python")
  ...
  return InstallResult(
      success=True,
      path=Path("frida-python"),
      version=version,
  )
  ```

- **Why this is non-functional:** Frida is a Python package, not a filesystem layout, but the API contract returns `Path | None`. `Path("frida-python")` is a magic string that `verify_tool` checks via equality. Any caller that treats the returned `Path` as a real filesystem location operates on a relative directory that does not exist. If a user happens to have a directory named `frida-python` in CWD, the equality check still succeeds incorrectly.
- **Callers / blast radius:** `src/intellicrack/bridges/installer.py:316,460,566` and any consumer of `find_tool`/`install_tool`.
- **Suggested remediation summary:** Track Frida availability with a separate boolean/version field.

#### F-0003 - install_tool reports success even when version verification cannot be performed [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 523-534
- **Pattern:** Cat 2, "Return success when post-condition was not actually verified"
- **Why this is non-functional:** `success=True` is returned unconditionally after extraction even if `get_version` returned `None` or the executable cannot be located. A failed extraction that yields no executables is reported as a successful install.
- **Callers / blast radius:** `src/intellicrack/bridges/installer.py:798-800` (`ensure_tool`); `src/intellicrack/ui/app.py:957`.

#### F-0004 - _install_frida treats successful pip exit as installed even when version probe fails [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 556-568
- **Pattern:** Cat 2, "Hardcoded success regardless of secondary check"
- **Why this is non-functional:** The version probe's `returncode` is never inspected. If the second subprocess fails, `stdout` is empty and `_parse_version` produces `ToolVersion(0,0,0)`. The function still returns `success=True`, masking failure modes.

### Category 4 - Ineffective / Naive Implementations

#### F-0005 - x64dbg version_command "-v" launches the GUI rather than printing a version [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 154-167
- **Pattern:** Cat 4, "Naive command that does not actually do what the comment claims"
- **Why this is non-functional:** x64dbg has no documented `-v` flag that prints a version and exits. Invoking `x64dbg.exe -v` from `get_version` will launch the x64dbg GUI (or be treated as a target file argument). The 30s subprocess timeout then trips while leaving a GUI window open. There is no fallback to parsing the `VERSIONINFO` PE resource.

#### F-0006 - Cutter version_command runs full Qt GUI binary just to read version [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 168-180
- **Pattern:** Cat 4, "Heavyweight subprocess for trivial query"
- **Why this is non-functional:** `cutter.exe --version` initialises Qt before printing the version line; on some builds it requires a display and may fail headless or pop windows briefly. There is no `--platform offscreen`, no `creationflags=CREATE_NO_WINDOW`, and no fallback parsing.

#### F-0007 - find_tool re-runs iterdir() inside the executables loop [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 280-292
- **Pattern:** Cat 4, "Naive O(N*M) scanning when a single pass would do"
- **Why this is non-functional:** `iterdir()` is invoked once per executable name, doing redundant directory enumeration on every iteration. Only one level of nesting is inspected, but Ghidra archives commonly expand into a `ghidra_X.Y_PUBLIC/ghidra_X.Y_PUBLIC/...` two-level layout that this misses.

#### F-0008 - GitHub asset selection uses fragile substring matches with no architecture check [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 609-620
- **Pattern:** Cat 4, "Fragile heuristic that breaks on upstream rename"
- **Why this is non-functional:** Cutter publishes both `Cutter-vX.Y.Z-Windows-x86_64.zip` and `Cutter-vX.Y.Z-Windows-i686.zip`; this picks the first regardless of host arch and can install 32-bit on a 64-bit system. No fallback if upstream renames assets, no SHA verification, no GitHub auth header.

#### F-0009 - "python" and "pip" used instead of sys.executable / venv pip [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 187, 307, 551, 558
- **Pattern:** Cat 4, "Bare command name relies on PATH and may target wrong interpreter"
- **Why this is non-functional:** On Windows the `python` and `pip` binaries on PATH may be the launcher stub, an unrelated interpreter, or absent in pixi/conda environments. Standard pattern is `[sys.executable, "-m", "pip", ...]`.

#### F-0010 - send_command increments_next_id outside the lock

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 198-211
- **Pattern:** Cat 4, "Naive sequencing that allows ID/order skew"
- **Why this is non-functional:** Two concurrent `send_command` callers can both compute `request_id` before either acquires `self._lock`; the on-wire order does not match ID order.

### Category 5 - Error Handling Anti-Patterns

#### F-0011 - ensure_tool drops original install error when raising [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 791-802
- **Pattern:** Cat 5, "Re-raise generic exception, swallowing root cause"
- **Why this is non-functional:** `result.error` contains the actual reason but the function raises with the constant string `"failed to ensure tool"`. UI and logs lose all diagnostic context.

#### F-0012 - _find_frida treats TimeoutExpired identically to "frida not installed" [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 297-316
- **Pattern:** Cat 5, "Conflate distinct failure modes into single None return"
- **Why this is non-functional:** A 10s timeout typically indicates a hanging interpreter (slow import, AV interference), not absence. Returning None lumps it with `FileNotFoundError`.

#### F-0013 - send_command Raises clauses missing from docstring

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 185-198
- **Pattern:** Cat 5, "Documented contract omits exceptions actually thrown"

#### F-0014 - event_handler exceptions propagate and corrupt request stream

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 210-221
- **Pattern:** Cat 5, "Untrusted callback invoked without exception isolation"
- **Why this is non-functional:** The user-supplied event handler is invoked synchronously inside the lock. If it raises, the exception escapes from `send_command`, the response message that was about to arrive is discarded.

#### F-0015 - close() does not wait for in-flight send_command

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 176-183
- **Pattern:** Cat 5, "Lifecycle teardown ignores ongoing operations"

### Category 6 - Resource & Lifecycle Issues

#### F-0016 - cancelled connect() may leak the pipe handle

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 161-174
- **Pattern:** Cat 6, "asyncio cancellation can leave a real OS handle open"

#### F-0017 - _close_handle does not check the CloseHandle return value

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 395-406
- **Pattern:** Cat 6, "Ignored Win32 cleanup error"

#### F-0018 - download_file leaves partial files on failure [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 640-675
- **Pattern:** Cat 6, "Temp file not cleaned up on error path"

#### F-0019 - Unbounded growth of _next_id and lack of wraparound handling

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 120, 199-200
- **Pattern:** Cat 6, "Counter never reset / no overflow strategy"

### Category 7 - Concurrency / Async Issues

#### F-0020 - Synchronous event_handler called inside the I/O lock

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 210-218
- **Pattern:** Cat 7, "Long-running synchronous callback under async lock"

#### F-0021 - Single global lock serialises all pipe commands; events block requests

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 118, 210-221
- **Pattern:** Cat 7, "Coarse lock granularity blocks unrelated work"

#### F-0022 - download progress logging branch fires unreliably [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 655-662
- **Pattern:** Cat 7, "Modulo trick for progress can fire 0 or many times per MB"

### Category 9 - Bridge / Tool Integration Failures

#### F-0023 - Hardcoded pipe name prevents multi-instance / multi-tenant use

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 92
- **Pattern:** Cat 9, "Bridge endpoint cannot accommodate two of the tool"

#### F-0024 - _open_handle uses share_mode=0 (exclusive) - blocks legitimate reconnects

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 368-376
- **Pattern:** Cat 9, "Wrong CreateFile share-mode parameter"

#### F-0025 - deploy_x64dbg_plugin requires write to Program Files without admin check [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 1051-1077
- **Pattern:** Cat 9, "Bridge install path requires elevated rights but does not check"

#### F-0026 - cmake/build feedback dropped on plugin build failure [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 942-986
- **Pattern:** Cat 9, "Subprocess output discarded so failures cannot be diagnosed"

### Category 10 - Subprocess / External Process Issues

#### F-0027 - cmake configure timeout (120 s) is too tight for cold runs [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 947-973
- **Pattern:** Cat 10, "Hardcoded timeout fails on slow / first-time runs"

#### F-0028 - _find_cmake silently returns None on vswhere failure [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 846-861
- **Pattern:** Cat 10, "Silent except: pass on subprocess fallback"

### Category 13 - Logging / Observability Theater

#### F-0029 - Per-chunk pipe write logging at INFO level

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 499-528
- **Pattern:** Cat 13, "Routine I/O at INFO floods logs"

#### F-0030 - exception wrapped only as str(exc), losing stack trace in InstallResult.error [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 536-538, 575-577
- **Pattern:** Cat 13, "Stringified exception loses traceback"

### Category 15 - Platform / Windows Compatibility

#### F-0031 - find_tool common_paths use POSIX-style executable for Ghidra alongside .bat [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 149
- **Pattern:** Cat 15, "POSIX-only entry intermixed with Windows entry"

#### F-0032 - Inconsistent Windows guard: os.name vs sys.platform

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 145-153, 345-347, 404-405, 428-430, 493-495
- **Pattern:** Cat 15, "Inconsistent platform predicate"

#### F-0033 - vswhere PROGRAMFILES(X86) lookup uses literal English fallback [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 842
- **Pattern:** Cat 15, "Hardcoded English path"

### Category 16 - Binary Analysis-Specific Failures

#### F-0034 - get_version subprocess can launch GUI tools mid-analysis [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 335-357
- **Pattern:** Cat 16, "Launching debugger/disassembler binary as a probe"

### Category 19 - Data Parsing / Format Issues

#### F-0035 - _parse_version returns ToolVersion(0,0,0) for any unparseable input [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 422-440
- **Pattern:** Cat 19, "Lossy parser silently downgrades to zero version"

#### F-0036 - x64dbg snapshot version strings parsed as semver fail min_version comparison [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 165-167, 422-440, 466-477
- **Pattern:** Cat 19, "min_version field uses date format that the parser interprets as semver"

### Category 20 - Dead Code & Unreachable Paths

#### F-0037 - Tool registry omits SANDBOX and HEX_EDITOR enum members [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 138-199, 252-256, 812-820
- **Pattern:** Cat 20, "Switch over enum missing members; default path returns None silently"

#### F-0038 - _PLUGIN_ARCHS third tuple field is unused [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 823-826, 1042-1043
- **Pattern:** Cat 20, "Dead struct field never consumed"

### Category 21 - Documentation / Signature Drift

#### F-0039 - send_command docstring missing Raises section despite raising paths

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 185-198
- **Pattern:** Cat 21, "Docstring missing Raises clauses"

#### F-0040 - close() docstring omits the I/O thread-pool side effects

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 176-183
- **Pattern:** Cat 21, "Docstring under-specifies behaviour"

#### F-0041 - get_version docstring claims behaviour the code does not deliver for x64dbg [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 154-167, 318-327
- **Pattern:** Cat 21, "Comment/docstring claims behaviour the code does not deliver"

### Category 24 - Recovery / Robustness Theater

#### F-0042 - _PIPE_ERROR_HINTS only covers 3 of the common pipe errors

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 323-327
- **Pattern:** Cat 24, "User-facing diagnostics list looks helpful but is incomplete"

#### F-0043 - deploy_x64dbg_plugin returns True when one arch is up-to-date even if other arches failed [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 1042-1078
- **Pattern:** Cat 24, "Aggregated boolean obscures partial failure"

#### F-0044 - _extract_archive returns tool_dir when no subdir was extracted [obsolete: c0167a39]

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 698-709
- **Pattern:** Cat 24, "Fallback that masks bad archive contents"

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

#### F-0001 - `clipboard_monitor.ps1` fallback polling loop is unreachable [obsolete: 75faa1d448216e62b4fd77a529a2026ce79b8c16]

- **File:** `src/intellicrack/sandbox/scripts/clipboard_monitor.ps1`
- **Lines:** 73-85
- **Pattern:** Cat 20
- **Why this is non-functional:** The file-level `$ErrorActionPreference = 'SilentlyContinue'` means most `Add-Type` failures will never throw, so the `catch` (and its polling fallback) is unreachable in practice.

### Category 5 - Swallowed Errors

#### F-0002 - `clipboard_monitor.ps1` blanket `SilentlyContinue` swallows all real errors [obsolete: 75faa1d448216e62b4fd77a529a2026ce79b8c16]

- **File:** `src/intellicrack/sandbox/scripts/clipboard_monitor.ps1`
- **Lines:** 1
- **Pattern:** Cat 5

### Category 12 - Configuration Drift

#### F-0003 - `clipboard_monitor.ps1` hardcoded log path conflicts with caller-supplied `-LogDir` [obsolete: 75faa1d448216e62b4fd77a529a2026ce79b8c16]

- **File:** `src/intellicrack/sandbox/scripts/clipboard_monitor.ps1`
- **Lines:** 3
- **Pattern:** Cat 12

### Category 16 - Broken Control Flow

#### F-0004 - `clipboard_monitor.ps1` clobbers PowerShell automatic variable `$pid` [obsolete: 75faa1d448216e62b4fd77a529a2026ce79b8c16]

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

# Findings: core-analysis

## Files audited (8)

- src/intellicrack/core/analysis_aggregator.py
- src/intellicrack/core/disassembler.py
- src/intellicrack/core/yara_scanner.py
- src/intellicrack/core/transform_pipeline.py
- src/intellicrack/core/script_gen.py
- src/intellicrack/core/template_manager.py
- src/intellicrack/core/_xml_gen.py
- src/intellicrack/core/_xml_gen.pyi

## Findings

### Category 1 - Empty / Stub Implementations

#### F-0001 - ScriptGenerator.**init** has empty body and class is a no-op shell

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 805-826
- **Pattern:** Cat 1
- **Excerpt:**

  ```python
  class ScriptGenerator:
      """Stable public entry point for building AI prompts that generate scripts.
      ...
      """

      def __init__(self) -> None:
          """Initialize the ScriptGenerator instance."""

      @staticmethod
      def prepare_ai_prompt(context: ScriptContext, language: ScriptLanguage) -> str:
  ```

- **Why this is non-functional:** Empty `__init__`, every public method is `@staticmethod` or could be, the class adds no behaviour over module-level functions. Stub class wrapped in fictional architectural narrative.
- **Callers / blast radius:** `src/intellicrack/main.py:659`, `src/intellicrack/ui/app.py`, `src/intellicrack/ui/tools.py`, `src/intellicrack/ui/panels/script_manager.py`, `src/intellicrack/core/orchestrator.py`.

### Category 2 - Hardcoded Return Values & Fake Success

#### F-0002 - Default fallback architecture silently coerces unrecognised binaries to x86-64

- **File:** `src/intellicrack/core/disassembler.py`
- **Lines:** 58-59, 316-320
- **Pattern:** Cat 2
- **Excerpt:**

  ```python
  _CAPSTONE_DEFAULT_ARCH_MODE: tuple[str, str] = ("x86", "64")
  ...
      result = _CAPSTONE_ARCH_MODE_MAP.get(arch)
      if result is None:
          _logger.debug("arch_detection_fallback", reason="unrecognised binary format")
          return _CAPSTONE_DEFAULT_ARCH_MODE
      return result
  ```

- **Why this is non-functional:** Unknown architectures get x86-64; downstream `disassemble()` produces structurally well-formed but semantically nonsense output - real instructions interpreted as x86. The log is `debug`-level so silent misclassification doesn't surface.

#### F-0003 - ScriptValidator.validate returns success for unknown languages without checking

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 487-511
- **Pattern:** Cat 2
- **Excerpt:**

  ```python
  if validator := validators.get(script.language):
      ...
  _logger.debug("script_validation_skipped", script=script.name, language=script.language.value)
  script.verified = True
  return True, None
  ```

- **Why this is non-functional:** R2_COMMANDS and X64DBG_SCRIPT have no validator; method sets `script.verified = True` regardless. The `verified` attribute means "we did not look".

### Category 4 - Ineffective / Naive Implementations

#### F-0004 - validate_java uses substring containment for "import" and "public"

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 462-485
- **Pattern:** Cat 4
- **Excerpt:**

  ```python
  if "import" not in content:
      ...
      return False, "Missing required element: import"

  if "public" not in content:
      ...
      return False, "Missing required element: public"
  ```

- **Why this is non-functional:** `"import"`/`"public"` substring matches succeed inside string literals/comments/identifiers. Brace counting rejects `String s = "}"` as unbalanced.

#### F-0005 - Aggregator deduplicates imports/exports by address only

- **File:** `src/intellicrack/core/analysis_aggregator.py`
- **Lines:** 203-236
- **Pattern:** Cat 4
- **Excerpt:**

  ```python
  def _deduplicate_imports(imports: list[ImportInfo]) -> list[ImportInfo]:
      seen: set[int] = set()
      result: list[ImportInfo] = []
      for imp in imports:
          if imp.address not in seen:
              seen.add(imp.address)
              result.append(imp)
      return result
  ```

- **Why this is non-functional:** Imports with `address == 0` (unbound, by-ordinal) all collapse to one. Forwarder exports on the same trampoline get coalesced. Natural key should be `(dll, function, ordinal)`.

### Category 11 - Persistence / State Issues

#### F-0006 - reload_script ignores subdir saves and silently fails

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 681-711
- **Pattern:** Cat 11
- **Excerpt:**

  ```python
  def reload_script(self, name: str) -> bool:
      ...
      ext = script.get_extension()
      filename = f"{name}{ext}"
      path = self.scripts_dir / filename
      if not path.exists():
          _logger.debug("script_reload_file_missing", script=name, path=str(path))
          return False
  ```

- **Why this is non-functional:** `save_script(name, subdir="...")` writes to `scripts_dir / subdir / filename`, but `reload_script` only ever looks at `scripts_dir / filename`. Any script saved with a subdir is unreloadable.

### Category 13 - Logging / Observability Theater

#### F-0007 - Script.save logs "script_file_written" before the file is actually written

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 333-343
- **Pattern:** Cat 13
- **Excerpt:**

  ```python
  def save(self, path: Path) -> None:
      path.parent.mkdir(parents=True, exist_ok=True)
      _logger.debug("directory_ensured", directory=str(path.parent))
      _logger.info("script_file_written", path=str(path), size=len(self.content))
      path.write_text(self.content, encoding="utf-8")
      _logger.info("script_saved", path=str(path), size=len(self.content))
  ```

- **Why this is non-functional:** Line 341 emits `script_file_written` BEFORE write. If write raises, observability sees "file written" event followed by no "script_saved" event - and no error event because no `except`.

#### F-0008 - TemplateManager logs "file_written" before write completes

- **File:** `src/intellicrack/core/template_manager.py`
- **Lines:** 230-245, 313-334
- **Pattern:** Cat 13

#### F-0009 - disassemble_to_lines logs constant `binary_path="<bytes-buffer>"`

- **File:** `src/intellicrack/core/disassembler.py`
- **Lines:** 279-289
- **Pattern:** Cat 13

#### F-0010 - validate_javascript logs `temp_file_unlink` and `temp_file_cleaned` around the same call

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 438-441
- **Pattern:** Cat 13

### Category 14 - Security / Crypto Failures

#### F-0011 - _xml_gen obfuscates xml.etree import to evade bandit B405

- **File:** `src/intellicrack/core/_xml_gen.py`
- **Lines:** 1-32
- **Pattern:** Cat 14
- **Excerpt:**

  ```python
  """XML generation utilities wrapper.
  ...
  Uses runtime string construction to avoid B405 bandit finding. ...
  """
  import importlib

  _et = importlib.import_module("xml.etree" + "." + "ElementTree")

  Element = _et.Element
  ```

- **Why this is non-functional:** Concatenating `"xml.etree" + "." + "ElementTree"` and feeding to `importlib.import_module` loads the same vulnerable module - just hides it from the linter. CLAUDE.md forbids this kind of suppression.

### Category 21 - Documentation / Signature Drift

#### F-0012 - script_gen module docstring promises script execution that does not exist

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 5-31
- **Pattern:** Cat 21
- **Why this is non-functional:** Closing bullet promises "Script management (save, load, execute)" but no `execute` method exists on `ScriptManager`.

#### F-0013 - Script.created_at uses naive datetime.now while last_run uses UTC

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 295-331
- **Pattern:** Cat 21
- **Excerpt:**

  ```python
  created_at: datetime = field(default_factory=datetime.now)
  ...
  self.execution_results["last_run"] = datetime.now(tz=UTC).isoformat()
  ```

- **Why this is non-functional:** Mixing tz-aware and tz-naive datetimes causes `TypeError` on subtraction.

### Category 22 - Test / Debug Code Leaked

#### F-0014 - Inline comment in reload_script admits broken implementation

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 690-692
- **Pattern:** Cat 22
- **Excerpt:**

  ```python
      # First try to find where it might be saved
      # This is a bit tricky since save_script logic handles paths
      # We assume standard location in scripts_dir
      _logger.debug("script_reload_start", script=name)
  ```

- **Why this is non-functional:** Apology comments left in production. CLAUDE.md forbids TODO comments.

### Category 24 - Recovery / Robustness Theater

#### F-0015 - AnalysisAggregator continues with BinaryInfo only and reports a "summary" that may be empty

- **File:** `src/intellicrack/core/analysis_aggregator.py`
- **Lines:** 95-120
- **Pattern:** Cat 24
- **Excerpt:**

  ```python
  if not source_bridges:
      source_bridges.append("binary_info")
      notes.append("No bridges connected; using BinaryInfo metadata only")
  ...
  return BridgeAnalysisSummary(
      binary_name=binary_name,
      strings=strings,
      ...
      source_bridges=source_bridges,
      analysis_notes=notes,
  )
  ```

- **Why this is non-functional:** When no bridge contributed, returns summary with empty strings/functions but appears successful. AI report generation produces empty report presented as authoritative.

# Findings: ui-panels-main

## Files audited (18)

- src/intellicrack/ui/panels/**init**.py
- src/intellicrack/ui/panels/analysis_panel.py
- src/intellicrack/ui/panels/async_bridge.py
- src/intellicrack/ui/panels/base_panel.py
- src/intellicrack/ui/panels/cutter_panel.py
- src/intellicrack/ui/panels/cutter_tabs.py
- src/intellicrack/ui/panels/frida_panel.py
- src/intellicrack/ui/panels/ghidra_panel.py
- src/intellicrack/ui/panels/graph_view.py
- src/intellicrack/ui/panels/hex_editor_panel.py
- src/intellicrack/ui/panels/hex_editor_widget.py
- src/intellicrack/ui/panels/hxd_panel.py
- src/intellicrack/ui/panels/qt_compat.py
- src/intellicrack/ui/panels/sandbox_panel.py
- src/intellicrack/ui/panels/script_manager.py
- src/intellicrack/ui/panels/stack_viewer.py
- src/intellicrack/ui/panels/vnc_widget.py
- src/intellicrack/ui/panels/x64dbg_panel.py

## Summary

This slice is unusually well wired: every toolbar button, context-menu action, and tab refresh in `cutter_panel.py`, `ghidra_panel.py`, `frida_panel.py`, `x64dbg_panel.py`, and `sandbox_panel.py` dispatches to a real bridge coroutine. Spot checks against bridge module surfaces confirmed every called method exists.

## Findings

### Category 20 - Dead Code / Unreachable Feature

#### F-0001 - HxDPanel is implemented but never imported, instantiated, or exposed by the panels package

- **File:** `src/intellicrack/ui/panels/hxd_panel.py`
- **Lines:** 102-352
- **Pattern:** Cat 20

### Category 1 - Empty / Stub Implementations

#### F-0002 - SandboxPanel exposes deprecated SandboxBase / SandboxManager setters that only emit a warning and store an unreachable backend

- **File:** `src/intellicrack/ui/panels/sandbox_panel.py`
- **Lines:** 358-383
- **Pattern:** Cat 1

### Category 9 - Bridge Integration

#### F-0003 - SandboxPanel VNC autoconnect never forwards the QEMU VNC password

- **File:** `src/intellicrack/ui/panels/sandbox_panel.py`
- **Lines:** 1664-1678 (with `vnc_widget.py:675`)
- **Pattern:** Cat 9
- **Why this is non-functional:** When the QEMU sandbox is configured with `-vnc :N,password=on`, the RFB handshake falls through `_perform_vnc_auth` -> `vnc_auth_missing_password` and the widget silently disconnects.

### Category 6 - Resource & Lifecycle Issues

#### F-0004 - SandboxPanel cleanup path destroys the sandbox without first stopping an active PCAP capture

- **File:** `src/intellicrack/ui/panels/sandbox_panel.py`
- **Lines:** 326-339
- **Pattern:** Cat 6

### Category 2 - Hardcoded Return Values

#### F-0005 - GhidraPanel.refresh of labels uses 0 as a fallback address when the input is empty, silently changing the user's intent

- **File:** `src/intellicrack/ui/panels/ghidra_panel.py`
- **Lines:** 2264-2276
- **Pattern:** Cat 2

### Category 22 - Test/Debug Code

#### F-0006 - ScriptTypeInfo "x64dbg" template emits a self-contradictory bypass script

- **File:** `src/intellicrack/ui/panels/script_manager.py`
- **Lines:** 166-185
- **Pattern:** Cat 22
- **Why this is non-functional:** The script first installs a breakpoint, then immediately overrides it with a conditional that requires `eax==1` *before the function has executed* (so the breakpoint never fires), and then unconditionally `run`s.

### Category 19 - Data Parsing / Format Issues

#### F-0007 - VNCWidget framebuffer pump silently drops every encoding except RAW, leaving the user with a frozen display

- **File:** `src/intellicrack/ui/panels/vnc_widget.py`
- **Lines:** 445-466
- **Pattern:** Cat 19

### Category 11 - Persistence / State Issues

#### F-0008 - SandboxPanel snapshot flow leaves _pending_snapshot_label non-None on error

- **File:** `src/intellicrack/ui/panels/sandbox_panel.py`
- **Lines:** 891-950
- **Pattern:** Cat 11
