> # Workgroup Directive — Execution Order 20/23: `ui-panels-process`
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
# Findings: ui-panels-process

## Files audited (8)

- src/intellicrack/ui/panels/process_panel/**init**.py
- src/intellicrack/ui/panels/process_panel/_base.py
- src/intellicrack/ui/panels/process_panel/_process_tab.py
- src/intellicrack/ui/panels/process_panel/_memory_tab.py
- src/intellicrack/ui/panels/process_panel/_threads_tab.py
- src/intellicrack/ui/panels/process_panel/_modules_tab.py
- src/intellicrack/ui/panels/process_panel/_system_tab.py
- src/intellicrack/ui/panels/process_panel/_workers.py

## Summary

Nearly every button on every tab dispatches an awaitable `ProcessBridge.*` coroutine through `run_bridge_coroutine_async`, and the bridge methods call real Win32 APIs. The critical attach/suspend/memory r/w/thread enum/DLL inject/handle enum paths all round-trip to real kernel calls. 26 functional gaps where panel state is fabricated, displayed-only, or ignored, and where bridge errors are swallowed silently.

## Findings

### Category 18 - GUI / UX Wiring Failures

#### F-0001 - `_status_arch` label is permanently `"Arch: --"` — never updated from the bridge

- **File:** `src/intellicrack/ui/panels/process_panel/_base.py`
- **Lines:** 195-249
- **Pattern:** Cat 18

#### F-0002 - `_status_priv` privilege label depends on a private bridge attribute that is never refreshed after a privilege change

- **File:** `src/intellicrack/ui/panels/process_panel/_base.py`
- **Lines:** 199-272
- **Pattern:** Cat 18

#### F-0003 - `MemoryTab._region_filter` filter input is never connected to anything

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 116-120, 365-392
- **Pattern:** Cat 18

#### F-0004 - `ModulesTab._mod_filter` filter input is never connected to anything

- **File:** `src/intellicrack/ui/panels/process_panel/_modules_tab.py`
- **Lines:** 118-122, 279-310
- **Pattern:** Cat 18

#### F-0005 - Memory tab actions are not gated on attachment — silent no-ops with no user feedback when not attached

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 49-95, 365-588
- **Pattern:** Cat 18

#### F-0006 - `MemoryTab._on_search` "Searching..." status never resets on failure

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 563-587
- **Pattern:** Cat 18

#### F-0007 - `MemoryTab._on_free` adds a new "Freed" row instead of removing the corresponding "Allocated" row

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 496-526
- **Pattern:** Cat 11

#### F-0008 - `_on_protect` and `_on_free` parse errors are logged but not surfaced

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 496-561
- **Pattern:** Cat 18

#### F-0009 - `MemoryTab._build_protect_tab` lacks a placeholder hint for the address field

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 293-297
- **Pattern:** Cat 18

#### F-0010 - `ThreadsTab._on_suspend_thread` / `_on_resume_thread` mislabeled — they suspend the entire process

- **File:** `src/intellicrack/ui/panels/process_panel/_threads_tab.py`
- **Lines:** 142-152, 386-396
- **Pattern:** Cat 18

#### F-0011 - `ThreadsTab._on_tls` reads the TID from the Fiber combo, not its own selector

- **File:** `src/intellicrack/ui/panels/process_panel/_threads_tab.py`
- **Lines:** 286-333, 544-570
- **Pattern:** Cat 18

#### F-0012 - `ThreadsTab` thread combos only update on explicit Refresh

- **File:** `src/intellicrack/ui/panels/process_panel/_threads_tab.py`
- **Lines:** 96-106, 353-384
- **Pattern:** Cat 11

#### F-0013 - `ProcessTab._inject_btn` does not require attachment and gives no feedback on failure or success

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 202-205, 501-523
- **Pattern:** Cat 18

#### F-0014 - `ProcessTab._on_filter_changed` fires a full bridge round-trip on every keystroke

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 153-158, 395-401
- **Pattern:** Cat 4

#### F-0015 - `ProcessTab._on_attach` does not surface failure

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 434-453
- **Pattern:** Cat 5

#### F-0016 - `ProcessTab._on_suspend`, `_on_resume`, `_on_terminate`, and `_load_process_info` silently consume bridge errors

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 465-549
- **Pattern:** Cat 5

#### F-0017 - `ProcessTab._on_terminate` only refreshes the system list, not the Tracked sub-tab

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 477-499
- **Pattern:** Cat 11

#### F-0018 - `ProcessTab._on_terminate` does not detach the panel state if the terminated PID is currently attached

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 477-499
- **Pattern:** Cat 11

#### F-0019 - `ThreadsTab._on_write_registers` reads only the Hex column — Decimal-column edits are silently dropped

- **File:** `src/intellicrack/ui/panels/process_panel/_threads_tab.py`
- **Lines:** 421-457
- **Pattern:** Cat 18

#### F-0020 - `SystemTab._on_pipe_close` removes the row before knowing whether the close succeeded

- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Lines:** 626-644
- **Pattern:** Cat 11, Cat 5

#### F-0021 - `SystemTab._on_job_info` appends to `_res_tree` instead of clearing it

- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Lines:** 727-764
- **Pattern:** Cat 18

#### F-0022 - `SystemTab` privileges, debug-enable, services, and PEB read ignore `_attached_pid is None`

- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Lines:** 472-587
- **Pattern:** Cat 18
- **Why this is non-functional:** `get_token_privileges(None)` and `adjust_token_privilege(..., pid=None)` operate on Intellicrack's own process when nothing is attached. The user sees a populated table and assumes it represents the target.

#### F-0023 - SystemTab queries swallow bridge errors silently

- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Lines:** 472-790
- **Pattern:** Cat 5

#### F-0024 - ModulesTab refreshes (handles, heaps, COM, .NET) all swallow bridge errors

- **File:** `src/intellicrack/ui/panels/process_panel/_modules_tab.py`
- **Lines:** 353-446
- **Pattern:** Cat 5

#### F-0025 - `_base._update_controls_for_state` enables/disables tab widgets but never enables/disables Process tab buttons

- **File:** `src/intellicrack/ui/panels/process_panel/_base.py`
- **Lines:** 158-272
- **Pattern:** Cat 18

#### F-0026 - `_workers.TrackedRefreshWorker` swallows all errors and emits an empty list

- **File:** `src/intellicrack/ui/panels/process_panel/_workers.py`
- **Lines:** 47-69
- **Pattern:** Cat 5
