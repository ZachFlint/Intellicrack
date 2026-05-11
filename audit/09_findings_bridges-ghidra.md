> # Workgroup Directive — Execution Order 09/23: `bridges-ghidra`
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
# Findings: bridges-ghidra

## Files audited (1)

- src/intellicrack/bridges/ghidra.py

## Summary

84 `_execute_remote(...)` call sites, virtually all relying on either (a) a trailing expression as the return value, or (b) inline indented script literals. Both patterns are systemically broken against the actual `ghidra_bridge`/`jfx_bridge` runtime. The headless launcher path is also broken end-to-end. 28 distinct findings below.

## Findings

### Category 9 - Bridge / Tool Integration Failures

#### F-0001 - Every `_execute_remote` call expecting a return value is broken: `remote_exec` discards trailing expression results

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 5956-5986 (definition); applied across the entire file
- **Pattern:** Cat 9
- **Why this is non-functional:** The bridge dispatches every Jython snippet through `bridge.remote_exec`. In `jfx_bridge.bridge.BridgeCommandHandlerThread.local_exec`, the remote handler runs the script with Python's `exec()` and returns `None` on success. Every script in this file ends with a trailing expression expecting that value to be returned, but `exec()` discards expression-statement results. So `_execute_remote(...)` always yields `None` for successful scripts, and every call site that does `cast("dict[str, Any]", result)` falls through the `if result else []` guard and returns an empty container regardless of the actual binary contents. The correct API is `bridge.remote_eval(...)`.
- **Callers / blast radius:** All 84 `_execute_remote(` call sites.
- **Suggested remediation summary:** Use `remote_eval` for value-returning scripts.

#### F-0002 - Indented multi-line scripts will raise `IndentationError` on the remote `exec`

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1771-1783, 1832-1860, 1926-1959, etc. (most call sites)
- **Pattern:** Cat 9
- **Why this is non-functional:** The Jython source is inlined inside the call expression, so every line carries 16+ leading spaces. When `remote_exec` ships the source, the receiver runs `exec(exec_expr, exec_globals)`. Python's compiler treats the first statement of a script as module-level; leading whitespace produces `IndentationError: unexpected indent`. With F-0001, the visible behaviour is "every call returns `None`/`[]` while a `ghidra_remote_exec_failed` exception is logged."
- **Suggested remediation summary:** Wrap each script in `textwrap.dedent(...)` or pull scripts into module-level constants.

#### F-0003 - `start_headless` deploys a bridge script that calls a non-existent constructor and a non-existent `start()` method

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1338-1371
- **Pattern:** Cat 9
- **Why this is non-functional:** `ghidra_bridge_server.GhidraBridgeServer` is a container class with no `__init__` accepting `server_host`/`server_port` and no instance method `start()`. The actual public API is `GhidraBridgeServer.run_server(server_host=..., server_port=..., background=False)`. So the post-script raises `TypeError: object() takes no parameters` immediately and headless exits without ever opening the bridge port.
- **Suggested remediation summary:** Replace body with `ghidra_bridge_server.GhidraBridgeServer.run_server(...)`.

#### F-0004 - `analyzeHeadless -postScript` does not keep the JVM alive

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1228-1255
- **Pattern:** Cat 9
- **Why this is non-functional:** `analyzeHeadless` is built to import/analyse a binary, run pre/post scripts, then exit. There is no `-import` argument here, so headless cannot operate. Even with a binary, headless exits after the post-script returns.

### Category 1 - Empty / Stub Implementations

#### F-0005 - `read_bytes` and many other methods relay results that will always be empty due to F-0001

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 3439-3480 (read_bytes); same shape across get_pcode, get_basic_blocks, get_slice, get_register_value, etc.
- **Pattern:** Cat 1
- **Why this is non-functional:** Because `_execute_remote` returns `None` (F-0001), the `isinstance(result, dict)` check is always false. The function therefore returns empty/zero data for every successful invocation.

### Category 5 - Error Handling Anti-Patterns

#### F-0006 - Functions swallow exceptions and return empty defaults so callers cannot distinguish "Ghidra error" from "no data"

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** Multiple lines across ~30 read methods
- **Pattern:** Cat 5
- **Why this is non-functional:** Docstrings advertise `Raises: ToolError: If Ghidra is not connected.` but the implementation catches every `Exception` and returns an empty list/dict.

#### F-0007 - `decompile` returns the literal string `"Decompilation failed"` instead of raising `ToolError`

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1953-1968
- **Pattern:** Cat 5
- **Why this is non-functional:** Three different failure modes collapse into one opaque string. Because of F-0001 the function returns `"Decompilation failed"` even when decompilation succeeds.

#### F-0008 - `analyze` claims success even when `analyzeAll` is dispatched but never confirmed

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1730-1747
- **Pattern:** Cat 2
- **Why this is non-functional:** `analyzeAll(currentProgram)` schedules analysis but does not block. Nothing waits on `AutoAnalysisManager.waitForAnalysis()`.

### Category 4 - Ineffective / Naive Implementations

#### F-0009 - `_create_bridge_script` writes the file without an explicit encoding and without `OSError` handling

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1338-1371
- **Pattern:** Cat 4

#### F-0010 - `search_bytes` falls back to silently returning `[]` for malformed hex tokens

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 2237-2277
- **Pattern:** Cat 4

#### F-0011 - `get_call_graph` / `get_call_tree` walk every address in a function body issuing per-byte ref lookups

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 3163-3223 (call_graph), 4412-4460 (call_tree)
- **Pattern:** Cat 4
- **Why this is non-functional:** Iterating every address and calling `getReferencesFrom` per byte is O(N*M) where N = function size in bytes. For a 5 KB function this is up to 5 000 lookups.

### Category 6 - Resource & Lifecycle Issues

#### F-0012 - `shutdown` does not close the `ghidra_bridge` RPC client; the socket leaks

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1147-1184
- **Pattern:** Cat 6

#### F-0013 - `shutdown` deletes the bridge script and its parent dir without serialising; concurrent `start_headless` calls race

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1167-1177
- **Pattern:** Cat 7

### Category 7 - Concurrency / Async Issues

#### F-0014 - `_wait_for_bridge_port` polls but never drains the subprocess's stderr; pipe fills and Ghidra hangs

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1287-1336
- **Pattern:** Cat 7

### Category 10 - Subprocess / External Process Issues

#### F-0015 - `Popen` invocation lacks `cwd`, env scrubbing, or `creationflags=CREATE_NO_WINDOW`

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1240-1255
- **Pattern:** Cat 10

#### F-0016 - `start_headless` resolves `analyzeHeadless.bat` then falls back to `analyzeHeadless` with no platform check

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1215-1221
- **Pattern:** Cat 15

### Category 14 - Security / Crypto Failures

#### F-0017 - MD5 (with `usedforsecurity=False`) is exposed in `BinaryInfo` next to SHA-256 as if it were an integrity field

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1437-1480
- **Pattern:** Cat 14

#### F-0018 - `import_debug_info` passes the path straight to Ghidra with no canonicalisation or existence check

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 3853-3992
- **Pattern:** Cat 14

### Category 13 - Logging / Observability Theater

#### F-0019 - `_logger.info("file_written", ...)` runs without verifying the write

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1357-1368
- **Pattern:** Cat 13

#### F-0020 - `set_label`, `add_comment`, `rename_function`, `create_bookmark`, `add_reference`, `create_equate`, `set_program_metadata` all return `success: True` without verifying remote outcome

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 2598-2623, 2335-2383, 2299-2333, 2665-2696, 3994-4038, 4188-4222, 5264-5301
- **Pattern:** Cat 2

### Category 15 - Platform / Windows Compatibility

#### F-0021 - `tempfile.gettempdir()` is shared across instances without race protection

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1354-1357
- **Pattern:** Cat 15

### Category 19 - Data Parsing / Format Issues

#### F-0022 - `get_xrefs_to` / `get_xrefs_from` collapse all reference types to `"call"` or `"data"` losing JUMP/READ/WRITE distinctions

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 2066-2076 and 2114-2124
- **Pattern:** Cat 19

### Category 20 - Dead Code & Unreachable Paths

#### F-0023 - `BridgeCapabilities.supports_patching=True` is reported but no `apply_patch`/`patch` method exists

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 108-127
- **Pattern:** Cat 20

#### F-0024 - `set_color` IntPropertyMap fallback returns `success: True` while having no visual effect in headless mode

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 5189-5256
- **Pattern:** Cat 20

### Category 21 - Documentation / Signature Drift

#### F-0025 - Docstrings universally promise `Raises: ToolError` but the implementation returns empty containers

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1749-1812 (`get_functions`) and ~30 other read methods
- **Pattern:** Cat 21

#### F-0026 - `get_xrefs_to` / `get_xrefs_from` advertise `from_function` / `to_function` enrichment but always set them to `None`

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 2034-2076 and 2082-2124
- **Pattern:** Cat 21

### Category 22 - Test / Debug Code Leaked Into Production

#### F-0027 - `analyze` writes `ghidra_analysis_complete` log without distinguishing analyser passes

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1742-1747
- **Pattern:** Cat 22

### Category 24 - Recovery / Robustness Theater

#### F-0028 - `decompile`, `read_bytes`, `disassemble` silently degrade to "no result" instead of escalating

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Lines:** 1903-1968 (decompile), 1970-2032 (disassemble), 3439-3480 (read_bytes)
- **Pattern:** Cat 24

## Cross-cutting key takeaways

The two file-wide defects (F-0001 wrong RPC method, F-0002 indented inline scripts) mean essentially every "analyze" / "decompile" / "get_*" / "search_*" / "create_*" / "set_*" method in this 5986-line bridge currently returns no useful data on a live ghidra_bridge connection. F-0003 plus F-0004 mean `start_headless` cannot launch a working bridge at all.
