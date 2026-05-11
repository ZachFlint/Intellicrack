> # Workgroup Directive — Execution Order 17/23: `core-orchestration`
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
# Findings: core-orchestration

## Files audited (8)

- src/intellicrack/core/orchestrator.py
- src/intellicrack/core/tools.py
- src/intellicrack/core/process_manager.py
- src/intellicrack/core/_subprocess.py
- src/intellicrack/core/session.py
- src/intellicrack/core/types.py
- src/intellicrack/core/config.py
- src/intellicrack/core/logging.py

## Findings

### Category 11 - Persistence / State Issues

#### F-0001 - `Orchestrator.load_session` never starts auto-save and bypasses the SessionManager's "current" pointer

- **File:** `src/intellicrack/core/orchestrator.py`
- **Lines:** 343-370
- **Pattern:** Cat 11
- **Why this is non-functional:** Calls `SessionManager.get()` which is documented as "without making it current", so `SessionManager._current` is left untouched and `_start_auto_save()` is never invoked.

### Category 21 - Documentation / Signature Drift

#### F-0002 - System prompt instructs the LLM to call non-existent `binary.*` tools

- **File:** `src/intellicrack/core/orchestrator.py`
- **Lines:** 720-741
- **Pattern:** Cat 21, Cat 17

### Category 16 - Binary Analysis-Specific Failures

#### F-0003 - `_extract_imports` / `_extract_exports` silently drop everything for Mach-O binaries

- **File:** `src/intellicrack/core/orchestrator.py`
- **Lines:** 1949-1983, 1986-2012
- **Pattern:** Cat 16, Cat 4

### Category 4 - Ineffective Implementations

#### F-0004 - Naive `len // 4` token estimate drives context-window trimming and "tokens used" stats

- **File:** `src/intellicrack/core/orchestrator.py`
- **Lines:** 791-800
- **Pattern:** Cat 4, Cat 13

### Category 11 - Persistence / State Issues (continued)

#### F-0005 - User message persists to the session even when the agent loop fails

- **File:** `src/intellicrack/core/orchestrator.py`
- **Lines:** 424-447
- **Pattern:** Cat 11, Cat 24

### Category 5 - Error Handling

#### F-0006 - Auto-save loop dies silently on the first failure

- **File:** `src/intellicrack/core/session.py`
- **Lines:** 1149-1153
- **Pattern:** Cat 5, Cat 24

### Category 20 - Dead Code

#### F-0007 - `Session.tool_states` is never written by the application

- **File:** `src/intellicrack/core/session.py`, `types.py`
- **Lines:** session.py 111, 304, 833, 873-877; types.py 1316-1331
- **Pattern:** Cat 20, Cat 11

#### F-0008 - `Session.tags` are stored but never assigned by any non-test code path

- **File:** `src/intellicrack/core/session.py`
- **Lines:** 115, 338-342, 829-830, 891
- **Pattern:** Cat 20

#### F-0009 - Duplicate `Session` dataclass in `types.py` shadows the real one and exports a stale shape

- **File:** `src/intellicrack/core/types.py`
- **Lines:** 1334-1361
- **Pattern:** Cat 20, Cat 8

### Category 12 - Configuration

#### F-0010 - `_default_providers()` omits two enum members (HUGGINGFACE, GROK)

- **File:** `src/intellicrack/core/config.py`
- **Lines:** 168-208
- **Pattern:** Cat 12

### Category 13 - Logging Theater

#### F-0011 - `_validate_tool_schemas` only logs warnings; broken schemas still go to the provider

- **File:** `src/intellicrack/core/orchestrator.py`
- **Lines:** 1243-1284
- **Pattern:** Cat 13, Cat 9

### Category 4 - Ineffective Implementations (continued)

#### F-0012 - `_is_destructive_operation` substring matching has unsafe false positives and false negatives

- **File:** `src/intellicrack/core/orchestrator.py`
- **Lines:** 173-186, 1318-1334
- **Pattern:** Cat 4, Cat 14
- **Why this is non-functional:** `frida.list_hooks` (read-only) flagged by "hook"; real destructive ops not in the list bypass confirmation: `sandbox.destroy`, `sandbox.snapshot_restore`, `process.kill_process`.

### Category 7 - Concurrency

#### F-0013 - `Orchestrator.shutdown`/`cancel` race against pending confirmation futures

- **File:** `src/intellicrack/core/orchestrator.py`
- **Lines:** 1796-1887, 1389-1396
- **Pattern:** Cat 7

### Category 11 - Persistence

#### F-0014 - `ProcessManager.register_external_pid` does not verify the PID exists

- **File:** `src/intellicrack/core/process_manager.py`
- **Lines:** 938-975
- **Pattern:** Cat 11, Cat 4

### Category 16 - Binary Analysis

#### F-0015 - `_extract_imports` for ELF binaries enumerates only PLT relocations

- **File:** `src/intellicrack/core/orchestrator.py`
- **Lines:** 1976-1983
- **Pattern:** Cat 16

### Category 12 - Configuration

#### F-0016 - `_default_log_dir()` uses `Path.cwd()` instead of the configured `logs_directory`

- **File:** `src/intellicrack/core/logging.py`
- **Lines:** 39-46, 360-393
- **Pattern:** Cat 12, Cat 11

### Category 9 - Bridge Integration

#### F-0017 - `Cutter` bridge is never auto-initialized despite being instantiated

- **File:** `src/intellicrack/core/tools.py`
- **Lines:** 105-150
- **Pattern:** Cat 9

### Category 13 - Logging Theater

#### F-0018 - `tool_status_check_failed` log uses wrong key naming convention; serialises enum repr instead of value

- **File:** `src/intellicrack/core/tools.py`
- **Lines:** 169-170, 391
- **Pattern:** Cat 13

### Category 4 - Ineffective Implementations

#### F-0019 - Missing context window silently disables trimming, sending unbounded history to provider

- **File:** `src/intellicrack/core/orchestrator.py`
- **Lines:** 802-892
- **Pattern:** Cat 4, Cat 17

### Category 6 - Resource & Lifecycle

#### F-0020 - `_atexit_cleanup` does redundant termination work that can block exit for tens of seconds

- **File:** `src/intellicrack/core/process_manager.py`
- **Lines:** 303-315, 379-392
- **Pattern:** Cat 6, Cat 24

#### F-0021 - `Config.parse_providers` drops user-defined providers not present in defaults

- **File:** `src/intellicrack/core/config.py`
- **Lines:** 341-368, 528-596
- **Pattern:** Cat 12

### Category 8 - Type Safety

#### F-0022 - `HexDocumentLike` / `HexDocumentFull` Protocol bodies provide concrete return values instead of `...`

- **File:** `src/intellicrack/core/types.py`
- **Lines:** 27-125
- **Pattern:** Cat 8, Cat 21

### Category 6 - Resource Lifecycle

#### F-0023 - `ToolRegistry.shutdown` does not clear `self._bridges`

- **File:** `src/intellicrack/core/tools.py`
- **Lines:** 195-205
- **Pattern:** Cat 6

### Category 7 - Concurrency

#### F-0024 - `SessionManager.update` performs blocking SQLite I/O on the event loop and races with auto-save

- **File:** `src/intellicrack/core/session.py`
- **Lines:** 1002-1009, 1132-1153
- **Pattern:** Cat 7, Cat 11

### Category 7 - Concurrency / Platform

#### F-0025 - `_signal_handler` synchronous fallback blocks inside the signal handler

- **File:** `src/intellicrack/core/process_manager.py`
- **Lines:** 277-302
- **Pattern:** Cat 7, Cat 15
