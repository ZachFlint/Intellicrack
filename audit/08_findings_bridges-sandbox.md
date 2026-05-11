> # Workgroup Directive — Execution Order 08/23: `bridges-sandbox`
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
# Findings: bridges-sandbox

## Files audited (1)

- src/intellicrack/bridges/sandbox_bridge.py

## Findings

### Category 5 - Error Handling Anti-Patterns

#### F-0001 - `cont()` only catches `SandboxError`; `QMPClient.cont()` can raise other exceptions

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1235-1247
- **Pattern:** Cat 5, Cat 24
- **Why this is non-functional:** `QMPClient.cont()` is an async TCP/JSON-RPC call that can realistically raise `ConnectionError`, `OSError`, `asyncio.TimeoutError`, `json.JSONDecodeError`, or `RuntimeError`. The docstring promises `Raises: ToolError`, but only `SandboxError` is wrapped.

#### F-0002 - Analysis bridge wrappers swallow only `(ValueError, KeyError, TypeError)`; other exceptions escape raw

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1614-1620, 1658-1664, 1711-1717, 1750-1756, 1804-1810
- **Pattern:** Cat 5, Cat 21

#### F-0003 - `detect_behaviors` silently discards bad rules files instead of erroring

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1702-1709
- **Pattern:** Cat 5, Cat 4
- **Why this is non-functional:** Three silent failure modes - missing path, wrong JSON shape, JSONDecodeError uncaught. Also the parameter description says "YAML file", but the loader uses `json.loads`.

### Category 19 - Data Parsing / Format Issues

#### F-0004 - `yara_scan` advertises `enum=["files","memory"]` but performs zero validation

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1548-1581 (vs. tool definition lines 550-557)
- **Pattern:** Cat 19, Cat 8

### Category 9 - Bridge / Tool Integration Failures

#### F-0005 - Bridge reaches into private QEMU sandbox attributes (`_qmp`, `_agent`)

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1236, 1290
- **Pattern:** Cat 9, Cat 24

### Category 13 - Logging / Observability Theater

#### F-0006 - `is_available`, `status`, `list` log `_logger.info("…_started")` on every call

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 701, 1012, 1022
- **Pattern:** Cat 13

### Category 4 - Ineffective / Naive Implementations

#### F-0007 - `get_vnc_port` accesses `instance.sandbox.vnc_port` for any sandbox type without checking VNC support

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1818-1846
- **Pattern:** Cat 4, Cat 21

#### F-0008 - `pcap_start`/`screenshot`/`memory_dump`/`extract_dropped_files`/`anti_evasion` accept any sandbox type without QEMU gating

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1313-1344, 1389-1427, 1429-1466, 1468-1506, 1508-1546
- **Pattern:** Cat 9, Cat 21

### Category 6 - Resource & Lifecycle Issues

#### F-0009 - `_ensure_manager()` silently re-creates the SandboxManager singleton, losing in-flight instance state

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 708-716
- **Pattern:** Cat 6, Cat 11

### Category 11 - Persistence / State Issues

#### F-0010 - `BridgeState` is wired once and never updated; `binary_loaded`/`target_path`/`target_pid`/`last_error` stay frozen

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 674-684, 692
- **Pattern:** Cat 11, Cat 18

### Category 21 - Documentation / Signature Drift

#### F-0011 - Tool-definition `default` values for `time_limit`, `output_path`, `args`, `categories` are absent

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 200-205, 215-219, 247-251, 444-453, 466-472, 506-511, 525-530, 583-589
- **Pattern:** Cat 21

### Category 4 - Ineffective / Naive Implementations (continued)

#### F-0012 - `extract_iocs`/`timeline`/`detect_behaviors`/`detect_c2`/`diff` re-import `intellicrack.sandbox.analysis` on every call

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 44-50, 1601, 1645, 1689, 1737, 1781
- **Pattern:** Cat 4, Cat 6

### Category 5 - Error Handling Anti-Patterns (continued)

#### F-0013 - `cont` returns `success=False` from QMP without raising; "vm_resumed" is logged unconditionally

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1241-1253
- **Pattern:** Cat 5, Cat 2

#### F-0014 - `get_pending_messages` builds `{"type": msg.msg_type, "data": msg.data}` outside the `try` block; AttributeErrors leak past the wrapper

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1295-1311
- **Pattern:** Cat 19, Cat 8

### Category 19 - Data Parsing / Format Issues (continued)

#### F-0015 - `_report_to_dict` emits `list(report.file_changes)` etc. — typed dataclasses, not JSON-serialisable dicts

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1862-1880
- **Pattern:** Cat 19, Cat 17
- **Why this is non-functional:** When the orchestrator passes the bridge return value through `json.dumps()` to send to an LLM provider, it raises `TypeError: Object of type FileChange is not JSON serializable`.

#### F-0016 - Timestamps in `list()` and `create()` emitted as `isoformat()` without timezone labelling in the schema

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 769-774, 1025-1035
- **Pattern:** Cat 21, Cat 19
