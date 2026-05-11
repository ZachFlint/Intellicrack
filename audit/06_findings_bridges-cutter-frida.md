> # Workgroup Directive — Execution Order 06/23: `bridges-cutter-frida`
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
# Findings: bridges-cutter-frida

## Files audited (2)

- src/intellicrack/bridges/cutter.py
- src/intellicrack/bridges/frida_bridge.py

## Findings

### Category 16 - Binary Analysis-Specific Failures

#### F-0001 - save_binary uses `wtf {target}` which only writes the current block, not the whole binary

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 2148-2167
- **Pattern:** Cat 16, Cat 2
- **Why this is non-functional:** Rizin's `wtf` is `wtf <filename> [size] @ [addr]` and writes the current block (default 256 bytes), NOT the full binary with cached patches applied. To save the loaded binary with `io.cache=true` patches you need `wcf <file>`.

#### F-0002 - assemble_at writes the assembled bytes twice (`wa` then `wx`)

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1703-1719
- **Pattern:** Cat 4, Cat 16

### Category 5 - Error Handling Anti-Patterns

#### F-0003 - get_imports/get_exports/get_sections silently return [] when not analyzed

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1568-1596
- **Pattern:** Cat 5, Cat 2

#### F-0004 - get_resources swallows ToolError and returns empty list

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 2018-2034
- **Pattern:** Cat 5, Cat 24

### Category 22 - Test/Debug Code Leaked

#### F-0005 - hook_function leaks default `console.log('[+] Called ...')` instrumentation in production

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 1948-2042
- **Pattern:** Cat 22, Cat 13

### Category 8 - Type Safety Violations

#### F-0006 - Tool definition for `frida.scan_memory` declares pattern as "string" but Python signature requires bytes

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 288-306, 1681-1745
- **Pattern:** Cat 8, Cat 21, Cat 9

### Category 16 - Binary Analysis-Specific Failures (continued)

#### F-0007 - Frida `call_function` returns `result.toInt32()` for pointer return types, truncating 64-bit values

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2174-2245
- **Pattern:** Cat 16, Cat 19
- **Why this is non-functional:** For `return_type == "pointer"` on a 64-bit process, the result is a `NativePointer`. Calling `.toInt32()` truncates to a 32-bit signed integer.

### Category 19 - Data Parsing / Format Issues

#### F-0008 - read_memory `data` key collides between binary side-channel and JSON payload `data` field

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 1551-1585, 2280-2297, 1828-1881
- **Pattern:** Cat 19, Cat 16

### Category 6 - Resource & Lifecycle Issues

#### F-0009 - enable_crash_reporting registers an unbounded callback handler with no idempotency or off-switch

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 3587-3632
- **Pattern:** Cat 6, Cat 11

#### F-0010 - Detached scripts left in `_alloc_scripts`/`_stalker_scripts`/`_call_probes` when `_unload_script` raises silently

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2363-2376, 1253-1258
- **Pattern:** Cat 6, Cat 5, Cat 24

### Category 9 - Bridge / Tool Integration Failures

#### F-0011 - resolve_symbol returns a fabricated `sub_<addr>` name when DebugSymbol resolution fails

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2821-2867
- **Pattern:** Cat 2, Cat 16

#### F-0012 - `compile_typescript` instantiates `frida.Compiler()` once per call without disposal

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 6157-6248
- **Pattern:** Cat 6, Cat 7

### Category 7 - Concurrency / Async Issues

#### F-0013 - Stalker.unfollow issued from a separate script, not the script that owns Stalker.follow

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 3357-3478, 3450-3457
- **Pattern:** Cat 7, Cat 16

#### F-0014 - `_make_payload_waiter` and `_make_install_waiter` capture `loop = asyncio.get_running_loop()` at construction

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2318-2361, 2489-2536
- **Pattern:** Cat 7

### Category 14 - Security / Crypto Failures

#### F-0015 - JS template strings interpolate integer parameters without explicit `int()` validation

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** Multiple — 1569-1572, 1604-1608, 2231-2235, 2687-2690, 3945-3955, 5435-5438, 5503-5510 and many others
- **Pattern:** Cat 14, Cat 8

#### F-0016 - search_string_live and search_assembly_pattern use unescaped user input as r2 commands

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 2864-2883, 2885-2904
- **Pattern:** Cat 14, Cat 19

### Category 19 - Data Parsing / Format Issues (continued)

#### F-0017 - `_cmd_json` returns silent `[]` on JSON parse failure, masking command errors

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1733-1761
- **Pattern:** Cat 19, Cat 5

#### F-0018 - MemoryRegion always sets `state="MEM_COMMIT", type="MEM_PRIVATE"` (Windows-only constants) regardless of platform

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 1655-1679, 5391-5411
- **Pattern:** Cat 2, Cat 15, Cat 21

### Category 4 - Ineffective Implementations

#### F-0019 - get_function_address triggers full functions enumeration, then filters in Python

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1802-1813
- **Pattern:** Cat 4

#### F-0020 - search_strings requires `_analyzed` but the underlying `izj` doesn't need analysis

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1389-1437, 1815-1850
- **Pattern:** Cat 5, Cat 4

### Category 5 - Error Handling Anti-Patterns (continued)

#### F-0021 - `_execute_script_and_wait` returns a result dict that "looks successful" after a timeout

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2247-2316
- **Pattern:** Cat 5, Cat 2

#### F-0022 - allocate_memory loop doesn't break after extracting addr; later error message can unload script after addr capture

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2693-2728, 3995-4029
- **Pattern:** Cat 6, Cat 5

### Category 24 - Recovery / Robustness Theater

#### F-0023 - Generic `except Exception` blocks throughout swallow Frida transport errors with only str() context

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** Multiple
- **Pattern:** Cat 5, Cat 24

#### F-0024 - shutdown() calls super().shutdown() AFTER releasing all references

- **Files:** `src/intellicrack/bridges/frida_bridge.py:1209-1292`, `src/intellicrack/bridges/cutter.py:878-895`
- **Pattern:** Cat 24, Cat 6

### Category 20 - Dead Code

#### F-0025 - `r2.setter` never used; the bridge writes to `self._r2` directly everywhere

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 757-774
- **Pattern:** Cat 20

### Category 18 - GUI / UX Wiring

#### F-0026 - Cutter bridge declares `supports_dynamic_analysis=False` but exposes 5 ESIL emulation tools

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 741-755, 2422-2519
- **Pattern:** Cat 18, Cat 21

### Category 11 - Persistence / State Issues

#### F-0027 - `_alloc_scripts` mapping never garbage-collects entries when the script unloads via other paths

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2669-2728, 3964-4029, 1253-1258
- **Pattern:** Cat 11, Cat 6

### Category 21 - Documentation / Signature Drift

#### F-0028 - `assemble_at` returns `bytes` but tool definition says "Assembled bytes"

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 382-390, 1680-1719
- **Pattern:** Cat 21, Cat 9

### Category 19 - Data Parsing

#### F-0029 - Cutter `is_64bit` heuristic compares `bits == 64` only

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 78-80, 990-1006, 1052-1065
- **Pattern:** Cat 16, Cat 19

### Category 5 - Error Handling

#### F-0030 - `attach()` calls `await self.initialize()` unconditionally; init errors masquerade as attach errors

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 1309-1351, 1352-1404, 1406-1490, 3083-3104, 4605-4630
- **Pattern:** Cat 5, Cat 6

### Category 2 - Hardcoded Returns

#### F-0031 - get_function returns hardcoded `0` for parameter and local variable size; fixed `location="stack"` for all params

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1145-1219, 1188-1206
- **Pattern:** Cat 2, Cat 16

### Category 4 - Ineffective Implementations

#### F-0032 - get_classes maps rizin `methods` and `fields` lists to ClassInfo as raw `list[Any]` without parsing

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1953-1977
- **Pattern:** Cat 4, Cat 19
