> # Workgroup Directive — Execution Order 14/23: `ui-panels-main`
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
