> # Workgroup Directive — Execution Order 02/23: `bridges-installer`
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
# Findings: bridges-installer

## Files audited (2)

- src/intellicrack/bridges/installer.py
- src/intellicrack/bridges/named_pipe_client.py

## Findings

### Category 2 - Hardcoded Return Values & Fake Success

#### F-0001 - PROCESS tool returns sentinel "builtin" path with no real validation

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

#### F-0002 - Frida "path" is the literal string "frida-python"

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

#### F-0003 - install_tool reports success even when version verification cannot be performed

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 523-534
- **Pattern:** Cat 2, "Return success when post-condition was not actually verified"
- **Why this is non-functional:** `success=True` is returned unconditionally after extraction even if `get_version` returned `None` or the executable cannot be located. A failed extraction that yields no executables is reported as a successful install.
- **Callers / blast radius:** `src/intellicrack/bridges/installer.py:798-800` (`ensure_tool`); `src/intellicrack/ui/app.py:957`.

#### F-0004 - _install_frida treats successful pip exit as installed even when version probe fails

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 556-568
- **Pattern:** Cat 2, "Hardcoded success regardless of secondary check"
- **Why this is non-functional:** The version probe's `returncode` is never inspected. If the second subprocess fails, `stdout` is empty and `_parse_version` produces `ToolVersion(0,0,0)`. The function still returns `success=True`, masking failure modes.

### Category 4 - Ineffective / Naive Implementations

#### F-0005 - x64dbg version_command "-v" launches the GUI rather than printing a version

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 154-167
- **Pattern:** Cat 4, "Naive command that does not actually do what the comment claims"
- **Why this is non-functional:** x64dbg has no documented `-v` flag that prints a version and exits. Invoking `x64dbg.exe -v` from `get_version` will launch the x64dbg GUI (or be treated as a target file argument). The 30s subprocess timeout then trips while leaving a GUI window open. There is no fallback to parsing the `VERSIONINFO` PE resource.

#### F-0006 - Cutter version_command runs full Qt GUI binary just to read version

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 168-180
- **Pattern:** Cat 4, "Heavyweight subprocess for trivial query"
- **Why this is non-functional:** `cutter.exe --version` initialises Qt before printing the version line; on some builds it requires a display and may fail headless or pop windows briefly. There is no `--platform offscreen`, no `creationflags=CREATE_NO_WINDOW`, and no fallback parsing.

#### F-0007 - find_tool re-runs iterdir() inside the executables loop

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 280-292
- **Pattern:** Cat 4, "Naive O(N*M) scanning when a single pass would do"
- **Why this is non-functional:** `iterdir()` is invoked once per executable name, doing redundant directory enumeration on every iteration. Only one level of nesting is inspected, but Ghidra archives commonly expand into a `ghidra_X.Y_PUBLIC/ghidra_X.Y_PUBLIC/...` two-level layout that this misses.

#### F-0008 - GitHub asset selection uses fragile substring matches with no architecture check

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 609-620
- **Pattern:** Cat 4, "Fragile heuristic that breaks on upstream rename"
- **Why this is non-functional:** Cutter publishes both `Cutter-vX.Y.Z-Windows-x86_64.zip` and `Cutter-vX.Y.Z-Windows-i686.zip`; this picks the first regardless of host arch and can install 32-bit on a 64-bit system. No fallback if upstream renames assets, no SHA verification, no GitHub auth header.

#### F-0009 - "python" and "pip" used instead of sys.executable / venv pip

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

#### F-0011 - ensure_tool drops original install error when raising

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 791-802
- **Pattern:** Cat 5, "Re-raise generic exception, swallowing root cause"
- **Why this is non-functional:** `result.error` contains the actual reason but the function raises with the constant string `"failed to ensure tool"`. UI and logs lose all diagnostic context.

#### F-0012 - _find_frida treats TimeoutExpired identically to "frida not installed"

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

#### F-0018 - download_file leaves partial files on failure

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

#### F-0022 - download progress logging branch fires unreliably

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

#### F-0025 - deploy_x64dbg_plugin requires write to Program Files without admin check

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 1051-1077
- **Pattern:** Cat 9, "Bridge install path requires elevated rights but does not check"

#### F-0026 - cmake/build feedback dropped on plugin build failure

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 942-986
- **Pattern:** Cat 9, "Subprocess output discarded so failures cannot be diagnosed"

### Category 10 - Subprocess / External Process Issues

#### F-0027 - cmake configure timeout (120 s) is too tight for cold runs

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 947-973
- **Pattern:** Cat 10, "Hardcoded timeout fails on slow / first-time runs"

#### F-0028 - _find_cmake silently returns None on vswhere failure

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 846-861
- **Pattern:** Cat 10, "Silent except: pass on subprocess fallback"

### Category 13 - Logging / Observability Theater

#### F-0029 - Per-chunk pipe write logging at INFO level

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 499-528
- **Pattern:** Cat 13, "Routine I/O at INFO floods logs"

#### F-0030 - exception wrapped only as str(exc), losing stack trace in InstallResult.error

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 536-538, 575-577
- **Pattern:** Cat 13, "Stringified exception loses traceback"

### Category 15 - Platform / Windows Compatibility

#### F-0031 - find_tool common_paths use POSIX-style executable for Ghidra alongside .bat

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 149
- **Pattern:** Cat 15, "POSIX-only entry intermixed with Windows entry"

#### F-0032 - Inconsistent Windows guard: os.name vs sys.platform

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 145-153, 345-347, 404-405, 428-430, 493-495
- **Pattern:** Cat 15, "Inconsistent platform predicate"

#### F-0033 - vswhere PROGRAMFILES(X86) lookup uses literal English fallback

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 842
- **Pattern:** Cat 15, "Hardcoded English path"

### Category 16 - Binary Analysis-Specific Failures

#### F-0034 - get_version subprocess can launch GUI tools mid-analysis

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 335-357
- **Pattern:** Cat 16, "Launching debugger/disassembler binary as a probe"

### Category 19 - Data Parsing / Format Issues

#### F-0035 - _parse_version returns ToolVersion(0,0,0) for any unparseable input

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 422-440
- **Pattern:** Cat 19, "Lossy parser silently downgrades to zero version"

#### F-0036 - x64dbg snapshot version strings parsed as semver fail min_version comparison

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 165-167, 422-440, 466-477
- **Pattern:** Cat 19, "min_version field uses date format that the parser interprets as semver"

### Category 20 - Dead Code & Unreachable Paths

#### F-0037 - Tool registry omits SANDBOX and HEX_EDITOR enum members

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 138-199, 252-256, 812-820
- **Pattern:** Cat 20, "Switch over enum missing members; default path returns None silently"

#### F-0038 - _PLUGIN_ARCHS third tuple field is unused

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

#### F-0041 - get_version docstring claims behaviour the code does not deliver for x64dbg

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 154-167, 318-327
- **Pattern:** Cat 21, "Comment/docstring claims behaviour the code does not deliver"

### Category 24 - Recovery / Robustness Theater

#### F-0042 - _PIPE_ERROR_HINTS only covers 3 of the common pipe errors

- **File:** `src/intellicrack/bridges/named_pipe_client.py`
- **Lines:** 323-327
- **Pattern:** Cat 24, "User-facing diagnostics list looks helpful but is incomplete"

#### F-0043 - deploy_x64dbg_plugin returns True when one arch is up-to-date even if other arches failed

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 1042-1078
- **Pattern:** Cat 24, "Aggregated boolean obscures partial failure"

#### F-0044 - _extract_archive returns tool_dir when no subdir was extracted

- **File:** `src/intellicrack/bridges/installer.py`
- **Lines:** 698-709
- **Pattern:** Cat 24, "Fallback that masks bad archive contents"
