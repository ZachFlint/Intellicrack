> # Workgroup Directive — Execution Order 16/23: `ui-app-core`
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
# Findings: ui-app-core

## Files audited (19)

- src/intellicrack/ui/**init**.py
- src/intellicrack/ui/_dialogs.py
- src/intellicrack/ui/_hex_format.py
- src/intellicrack/ui/_screen_compat.py
- src/intellicrack/ui/app.py
- src/intellicrack/ui/chat.py
- src/intellicrack/ui/confirmation_dialog.py
- src/intellicrack/ui/highlighter.py
- src/intellicrack/ui/panel_dock.py
- src/intellicrack/ui/preferences.py
- src/intellicrack/ui/provider_config.py
- src/intellicrack/ui/sandbox_config.py
- src/intellicrack/ui/session_manager.py
- src/intellicrack/ui/tool_config.py
- src/intellicrack/ui/tools.py
- src/intellicrack/ui/win32_embed.py
- src/intellicrack/ui/xpu_status.py
- src/intellicrack/ui/dialogs/**init**.py
- src/intellicrack/ui/dialogs/splash_screen.py

## Findings

### Category 18 - GUI / UX Wiring Defects

#### F-0001 - HxD toolbar button is permanently broken (target method does not exist)

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 743-747, 2095-2111
- **Pattern:** Cat 18
- **Why this is non-functional:** `add_hxd_tab` is never defined anywhere in the codebase. The toolbar exposes a prominent HxD button that, every single time the user clicks it, only calls `_show_tool_error("HxD", "HxD panel not available")`.

#### F-0002 - "Save Patched Binary..." menu item always reports "No hex editor loaded"

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1431-1446
- **Pattern:** Cat 18
- **Why this is non-functional:** `ToolOutputPanel.get_panel(panel_id)` returns from `self.panels`, but the hex editor is registered under `self.embedded_tools["hex_editor"]`, not `self.panels`.

#### F-0003 - Sandbox panel "active widget" lookup always returns None (wrong dict)

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 2283-2285
- **Pattern:** Cat 18

#### F-0004 - XPUStatusDialog is built and documented but never wired into any menu

- **File:** `src/intellicrack/ui/xpu_status.py`
- **Lines:** 83-105 (whole file, 401 lines)
- **Pattern:** Cat 18

#### F-0005 - FunctionListPanel and XRefPanel are wired but never populated with data

- **File:** `src/intellicrack/ui/tools.py`
- **Lines:** 845-851, 917-936
- **Pattern:** Cat 18

#### F-0006 - `_on_view_scripts` collects script panel state then discards it

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 548-556
- **Pattern:** Cat 13, Cat 18

#### F-0007 - "Tool Status..." menu prefetches statuses and pixmaps that are never passed to the dialog

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1482-1504
- **Pattern:** Cat 13, Cat 18

#### F-0008 - "Configure Tools..." dialog is created without the live tool registry

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1506-1514
- **Pattern:** Cat 18

#### F-0009 - `MainWindow._on_open_sandbox` constructs a throwaway SandboxConfigDialog just to call `is_sandbox_available()`

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1948-1956
- **Pattern:** Cat 11

#### F-0010 - `_apply_provider_settings` silently ignores providers that the user disables

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1602-1644
- **Pattern:** Cat 5

### Category 18 - Orphaned Signals (no slot connected)

#### F-0011 - `PreferencesDialog.settings_changed` signal has no consumers

- **File:** `src/intellicrack/ui/preferences.py`
- **Lines:** 461-464, 645-649

#### F-0012 - `SessionManagerDialog.session_loaded` and `session_deleted` signals have no consumers

- **File:** `src/intellicrack/ui/session_manager.py`
- **Lines:** 75-76, 515, 551

#### F-0013 - `ProviderConfigDialog.provider_updated` and `active_provider_changed` signals have no consumers

- **File:** `src/intellicrack/ui/provider_config.py`
- **Lines:** 962-963, 1277, 1345

#### F-0014 - `ModelSelectionDialog.model_selected` signal has no external consumers

- **File:** `src/intellicrack/ui/provider_config.py`
- **Lines:** 2647-2650, 2779

#### F-0015 - `SandboxConfigDialog.settings_updated` signal has no consumers

- **File:** `src/intellicrack/ui/sandbox_config.py`
- **Lines:** 280, 717

#### F-0016 - `SandboxMonitorWidget.sandbox_stopped` signal has no consumers

- **File:** `src/intellicrack/ui/sandbox_config.py`
- **Lines:** 886, 1016

#### F-0017 - `ToolConfigDialog.tool_updated` signal has no consumers

- **File:** `src/intellicrack/ui/tool_config.py`
- **Lines:** 745, 856

#### F-0018 - `ToolSettingsWidget.status_changed` signal has no consumers

- **File:** `src/intellicrack/ui/tool_config.py`
- **Lines:** 878, 1092

#### F-0019 - `ToolOutputPanel.embedded_tool_started` and `embedded_tool_closed` signals have no consumers

- **File:** `src/intellicrack/ui/tools.py`
- **Lines:** 775-776, 1098-1099

### Category 20 - Dead / Unreachable Code

#### F-0020 - `ToolConfirmationDialog.remember_similar` is captured but never read by callers

- **File:** `src/intellicrack/ui/confirmation_dialog.py`
- **Lines:** 73-80, 228-249
- **Pattern:** Cat 20

#### F-0021 - `ToolOutputPanel.wire_sandbox_backend` is a deprecated no-op never called

- **File:** `src/intellicrack/ui/tools.py`
- **Lines:** 2123-2133
- **Pattern:** Cat 20

### Category 4 - Ineffective / Naive Implementations

#### F-0022 - `ProviderSettingsWidget._setup_provider_specific_ui` only wires three of seven providers

- **File:** `src/intellicrack/ui/provider_config.py`
- **Lines:** 1670-1707
- **Pattern:** Cat 4

#### F-0023 - `MainWindow._on_browse_models_result` opens `ModelSelectionDialog` without provider context

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1756-1786
- **Pattern:** Cat 4

### Category 6 - Hardcoded / Environment-Specific Values

#### F-0024 - Hardcoded `D:/Intellicrack/...` paths in tool and sandbox defaults

- **Files:** `src/intellicrack/ui/tool_config.py:762`, `src/intellicrack/ui/sandbox_config.py:536`
- **Pattern:** Cat 6

### Category 13 - Logging / Observability Theater

#### F-0025 - `MainWindow._on_provider_changed` only logs the change

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 2347-2356
- **Pattern:** Cat 13

### Category 5 - Error Handling Anti-Patterns

#### F-0026 - `MainWindow._refresh_system_status` silently swallows errors and never disables the timer

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 838-858
- **Pattern:** Cat 5
