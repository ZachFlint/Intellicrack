# Intellicrack GUI Audit — Remediation Results (2026-07-02)

Remediation of every finding in `audit/gui-audit-2026-07-01.md`. Work was done
directly on `main`. Each finding ends in **FIXED** (code changed + a real
falsifiable test gate) or **WONTFIX** (with justification).

**Linters:** every modified/new source and test file passes `ruff`,
`basedpyright`, `pydoclint`, and `pydocstyle` with zero findings. No
suppressions were used and no lint config was weakened.

**Systemic fixes applied once and reused (DRY):**
- Cross-thread marshalling via `pyqtSignal` emitted from the callback thread to
  a GUI-thread slot (mirrors `FridaPanel._frida_message_received`).
- Theme-aware colour resolution through `ThemeManager.get_analysis_colors()` +
  subscription to `ThemeManager.theme_changed` for custom-painted widgets,
  the log model, and the syntax highlighters.
- Blocking bridge calls moved to the async worker path
  (`run_bridge_coroutine_logged`); `run_bridge_coroutine` gained an optional
  `timeout_s` for the rare synchronous case.

---

## CRITICAL / HIGH

| ID | Status | Files | Test gate |
|----|--------|-------|-----------|
| **H1** cross-thread UI mutation in `_on_bridge_analysis_received` | FIXED | `ui/app.py` | `tests/test_audit5/u5_ui_mainwindow/test_gui_audit_app_shell.py::test_h1_callback_only_emits_no_direct_widget_mutation`, `::test_h1_display_slot_performs_the_tab_update` |
| **H2** x64dbg debug-event `QTimer.singleShot` from bridge thread | FIXED | `ui/panels/x64dbg_panel.py` | `tests/test_audit7/ui_panels_process/test_gui_audit_debugger_x64dbg_panel.py` |
| **H3** hex-editor workers not stopped on teardown | FIXED | `ui/panels/hex_editor/panel.py` (+ worker attrs) | `tests/test_audit4/hex_editor_gui_audit/test_gui_audit_hexsub_cleanup.py` |
| **H4** log rows invisible in light theme | FIXED | `ui/log_viewer/_model.py` | `tests/test_ui/log_viewer/test_gui_audit_logtheme_model.py::test_info_and_debug_readable_in_both_themes` |

**H1** — the worker-thread callback now only emits `bridge_analysis_received`;
the tab clear/redisplay runs in the GUI-thread slot
`_on_bridge_analysis_displayed`. The redundant double-registration
(`set_bridge_analysis_callback` + `configure_hooks`) was removed — it wrote a
single attribute so it never double-fired.

**H2** — added `_debug_event_received = pyqtSignal(str)`; the bridge callback
emits it and a connected GUI-thread slot runs `_refresh_state()`.

**H3** — `_PENDING_WORKER_ATTRS` now covers all seven workers (statistics,
search, numeric, diff, strings, signatures, script); `_stop_pending_workers`
interrupts + bounded-waits each and `_cleanup` also removes the diff temp file.

**H4** — per-level colours resolve from `get_analysis_colors()`; the model
subscribes to `theme_changed` and re-emits `dataChanged` for the fg/bg roles.

---

## MEDIUM — thread-safety / freeze

| ID | Status | Files | Test gate |
|----|--------|-------|-----------|
| **M1** StackViewer blocking bridge on 500 ms timer | FIXED | `ui/panels/stack_viewer.py` | `tests/test_ui/test_gui_audit_debugger_stack_viewer.py` |
| **M2** 30 s status timer / Refresh Models block UI, no timeout | FIXED | `ui/app.py`, `ui/panels/async_bridge.py` | `test_gui_audit_app_shell.py::test_refresh_dispatches_async_and_never_blocks` + updated `test_ui_mainwindow.py` threshold/reset tests |
| **M3** VNC framebuffer QImage read/write race | FIXED | `ui/panels/vnc_widget.py` | `tests/test_ui/test_gui_audit_vncsandbox_m3_framebuffer.py` |
| **M4** synchronous VNC connect blocks GUI | FIXED | `ui/panels/vnc_widget.py` | `tests/test_ui/test_gui_audit_vncsandbox_m4_connect.py` |
| **M5** sandbox probe blocks GUI during dialog ctor | FIXED | `ui/sandbox_config.py`, `ui/tools.py` | `tests/test_ui/test_gui_audit_vncsandbox_m5_availability.py` |

**M2** — `_refresh_system_status` dispatches `get_system_status()` on the async
worker with an in-flight guard; results/errors marshal to GUI-thread slots
`_on_system_status_fetched` / `_on_system_status_error`. `discover_all()` on
Refresh Models moved to the non-blocking path.

**M3** — double-buffering: the bridge loop publishes a completed `QImage.copy()`
into a front buffer under a `threading.Lock`; `paintEvent` reads that snapshot
under the same lock, so no torn/freed buffer is ever painted.

**M5** — extracted a cached, thread-safe module-level
`is_windows_sandbox_available()` / `check_windows_sandbox_availability()`; the
dialog runs the probe asynchronously and `tools.py` calls the function directly
instead of constructing (and leaking) a throwaway `SandboxConfigDialog`.

---

## MEDIUM — wrong behaviour / wrong data

| ID | Status | Files | Test gate |
|----|--------|-------|-----------|
| **M6** Frida device combo always connects "local" | FIXED | `ui/panels/frida_panel.py` | `tests/test_bridge_completeness/frida/test_gui_audit_frida_device_hook_wiring.py` |
| **M7** register table shows 64-bit names for 32-bit targets | FIXED | `ui/panels/x64dbg_panel.py` | `test_gui_audit_debugger_x64dbg_panel.py` |
| **M8** thread combos reset on every auto-refresh | FIXED | `ui/panels/process_panel/threads_tab.py` | `tests/test_audit7/ui_panels_process/test_gui_audit_dialogs_threads_combo.py` |
| **M9** float numeric search truncated to int | FIXED | `ui/panels/hex_editor/search.py` | `tests/test_audit4/hex_editor_gui_audit/test_gui_audit_hexsub_numeric_float.py` |
| **M10** text search uses combo label not codec | FIXED | `ui/panels/hex_editor/search.py` | `tests/test_audit4/hex_editor_gui_audit/test_gui_audit_hexsub_encoding.py` |
| **M11** install path falls back to CWD when field empty | FIXED | `ui/tool_config.py` | `tests/test_audit5/u6_ui_tools/test_gui_audit_dialogs_tool_config.py` |
| **M12** restored "Auto-approve: ON" not applied at startup | FIXED | `ui/app.py` | `test_gui_audit_app_shell.py::test_m12_restored_on_state_applied_to_orchestrator_at_startup` |
| **M13** model selection lost on Refresh Models | FIXED | `ui/app.py` | `test_gui_audit_app_shell.py::test_m13_model_selection_preserved_across_refresh` |

**M6** — `_on_device_changed` reads the real device id/type from
`currentData()` and passes it to `connect_device`. **M7** — a `_GENERAL_REGS_32`
set is selected by `_is_64bit`; display names (`eax`/`eip`) map to the bridge's
normalised attrs, so x86 targets show correct registers and no bogus `r8`–`r15`.
**M9** — float/double route to native `search_numeric_float` (IEEE-754 match) or
the `struct f/d` fallback and are never coerced with `int()`. **M11** — the
stripped input string is tested before wrapping in `Path`, defaulting to
`tools/<tool_id>`.

---

## MEDIUM — graph / layout / parsing

| ID | Status | Files | Test gate |
|----|--------|-------|-----------|
| **M14** CFG `fit_to_view` fits stale scene rect | FIXED | `ui/panels/graph_view.py` | `test_gui_audit_ghidracutter_graph.py::TestSceneRectFollowsCurrentGraph` |
| **M15** Ghidra CFG never fit into view | FIXED | `ui/panels/ghidra_panel.py` | `test_gui_audit_ghidracutter_panels.py::TestApplyCfgFitsView` |
| **M16** function tree columns sort as strings | FIXED | `ui/panels/graph_view.py`, `ghidra_panel.py`, `cutter_panel.py` | `test_gui_audit_ghidracutter_graph.py::TestNumericSortTreeItem` |
| **M17** function filter fires RPC per keystroke | FIXED | `ui/panels/ghidra_panel.py`, `cutter_panel.py` | `test_gui_audit_ghidracutter_panels.py::TestFilterDebounce` |
| **M18** block dialogs parse input outside try/except | FIXED | `ui/panels/hex_editor/transforms.py` | `tests/test_audit4/hex_editor_gui_audit/test_gui_audit_hexsub_block_parse.py` |
| **M19** splash sized in physical px on HiDPI | FIXED | `ui/dialogs/splash_screen.py` | `tests/test_ui/test_gui_audit_dialogs_splash.py` |
| **M20** offset addresses painted with wrong colour | FIXED | `ui/panels/hex_editor_widget.py` | `tests/test_ui/test_gui_audit_hexwidget_paint_and_state.py` |
| **M21** EntropyMiniMap never fed / positioned off-widget | FIXED | `ui/panels/hex_editor_widget.py` | `tests/test_ui/test_gui_audit_hexwidget_paint_and_state.py` |

**M16** — a shared `NumericSortTreeItem` (in `graph_view.py`, imported by both
panels) overrides `__lt__` to compare Address as hex and Size as decimal.
**M20/M21** — offsets use the opaque `offset_text` colour (dynamic width also
fixes the >4 GB overrun); the minimap is fed via `set_entropy_data` and given a
right viewport margin so it renders inside the widget.

---

## LOW — cosmetic / edge-case / i18n / leaks

| Finding | Status | Files | Test gate |
|---------|--------|-------|-----------|
| graph_view `block_clicked` connected nowhere | FIXED | `graph_view.py`, `ghidra_panel.py`, `cutter_panel.py` | `test_gui_audit_ghidracutter_panels.py::TestBlockClickNavigation` |
| yara `goto_offset` empty stub | FIXED | `hex_editor/panel.py`, `hex_editor/yara.py` | `test_gui_audit_hexsub_yara_goto.py` |
| provider_config `objectName` overwritten | FIXED | `ui/provider_config.py` | `tests/test_audit5/u7_ui_providerconfig/test_gui_audit_dialogs_provider_config.py` |
| splitters collapsible to zero | FIXED | `ghidra_panel.py`, `cutter_panel.py`, `cutter_debugger_tab.py`, `cutter_search_tab.py`, `app.py` | `test_gui_audit_ghidracutter_panels.py::TestSplittersNotCollapsible` |
| highlighter hardcoded dark colours / no re-highlight | FIXED | `ui/highlighter.py` | `tests/test_ui/test_gui_audit_logtheme_highlighter.py` |
| highlighter `//` then `/*` mis-scan | FIXED | `ui/highlighter.py` | `test_gui_audit_logtheme_highlighter.py` (line-comment hides block-open) |
| status-bar labels clip, no tooltip | FIXED | `ui/app.py`, `ui/session_manager.py` | `test_gui_audit_app_shell.py` / `test_gui_audit_dialogs_provider_config.py` |
| memory-region dialog column sizing | FIXED | `ui/app.py` | covered in app-shell suite |
| sandbox result trees column sizing | FIXED | `ui/panels/sandbox_panel.py` | `tests/test_ui/test_gui_audit_vncsandbox_columns.py` |
| modules handles table column sizing | FIXED | `ui/panels/process_panel/modules_tab.py` | `tests/test_audit4/b5_modules_tab/test_gui_audit_dialogs_modules_handles.py` |
| log Time/Level column sizing | FIXED | `ui/log_viewer/window.py` | `tests/test_ui/log_viewer/test_gui_audit_logtheme_window.py` |
| session_manager double-stretch columns | FIXED | `ui/session_manager.py` | `test_gui_audit_dialogs_provider_config.py` peers |
| hex cursor rect one-glyph in multi-byte modes | FIXED | `ui/panels/hex_editor_widget.py` | `test_gui_audit_hexwidget_paint_and_state.py` |
| offset overrun for >4 GB files | FIXED | `ui/panels/hex_editor_widget.py` | `test_gui_audit_hexwidget_paint_and_state.py` |
| `set_selection_range` no emit/clamp | FIXED | `ui/panels/hex_editor_widget.py` | `test_gui_audit_hexwidget_paint_and_state.py` |
| `_modified_offsets` not remapped on insert/delete | FIXED | `ui/panels/hex_editor_widget.py` | `test_gui_audit_hexwidget_paint_and_state.py` |
| cutter ESIL `_esil_initialised` never reset | FIXED | `cutter_tabs.py`, `cutter_panel.py` | `test_gui_audit_ghidracutter_panels.py::TestEsilLatchReset` |
| graph block width fixed px/char | FIXED | `ui/panels/graph_view.py` | `test_gui_audit_ghidracutter_graph.py::TestBlockWidthFromFontMetrics` |
| script_manager r2 template indented | FIXED | `ui/panels/script_manager.py` | `tests/test_ui/test_gui_audit_ghidracutter_script_template.py` |
| chat `_scroll_to_bottom` before layout | FIXED | `ui/chat.py` | `tests/test_ui/test_gui_audit_dialogs_chat.py` |
| ghidra `tr(f"…")` runtime string | FIXED | `ui/panels/ghidra_panel.py` | `test_gui_audit_ghidracutter_panels.py::TestGhidraDeletePromptStaticTemplate` |
| provider/tool manual worker no isRunning guard | FIXED | `ui/provider_config.py`, `ui/tool_config.py` | `test_gui_audit_dialogs_provider_config.py` / `test_gui_audit_dialogs_tool_config.py` |
| log reload reader not `deleteLater`'d | FIXED | `ui/log_viewer/window.py` | `test_gui_audit_logtheme_window.py::test_reload_from_disk_deletes_old_reader` |
| xpu_status HTML injection (no escape) | FIXED | `ui/xpu_status.py` | `tests/test_ui/test_gui_audit_dialogs_xpu.py` |
| x64dbg embed poll not cancelled on teardown | FIXED | `ui/panels/x64dbg_panel.py` | `test_gui_audit_debugger_x64dbg_panel.py` |
| x64dbg apply_registers/disassembly stale on empty | FIXED | `ui/panels/x64dbg_panel.py` | `test_gui_audit_debugger_x64dbg_panel.py` |
| frida `_on_run_script_success` gratuitous raise | FIXED | `ui/panels/frida_panel.py` | `test_gui_audit_frida_device_hook_wiring.py` |
| frida async hook add/remove stale row indices | FIXED | `ui/panels/frida_panel.py` | `test_gui_audit_frida_device_hook_wiring.py` |

---

## Lower-confidence items

| Finding | Status | Notes |
|---------|--------|-------|
| `_request_tool_confirmation` `singleShot` on asyncio thread hangs | FIXED | Now marshals via `confirmation_requested` signal to a GUI-thread slot; future resolved with `loop.call_soon_threadsafe`. Gate: `test_gui_audit_app_shell.py::test_confirmation_marshals_via_signal_not_singleshot`. |
| double-registration via `set_bridge_analysis_callback` + `configure_hooks` | WONTFIX (cleaned) | `configure_hooks` merely re-calls `set_bridge_analysis_callback`, which writes a single attribute — no double-emit. The redundant call was removed for clarity. |

## Concurrency note

| Finding | Status | Notes |
|---------|--------|-------|
| hex-editor worker threads race the paint thread on `document.read` | WONTFIX | Verified against the Rust binding: `src/intellicrack-hexcore` contains **no `allow_threads`** call, so PyO3 holds the GIL across every `read`/`write_bytes`/`search_*`. Concurrent Python-visible access is therefore serialised by the GIL — no data race exists. If a future hexcore method adds `allow_threads`, this must be revisited. |

---

## Sandbox validation

All new/modified test gates were run in the Docker sandbox and pass. Because
several heavy UI test files share process-global singletons, they were validated
in directory-scoped groups (the project's normal grouping) rather than one giant
session. Representative counts: the combined `test_gui_audit_*` set reports
**155 passed** after the three test-harness fixes below; `test_gui_audit_app_shell.py`
6/6; the `RefreshSystemStatus` (M2) gates 3/3.

Three test-harness issues surfaced during validation and were fixed (source
fixes were already correct):
- `test_gui_audit_app_shell.py::test_m13…` populated the provider combo without
  blocking signals, firing the real `_on_provider_changed` modal; now wrapped in
  `QSignalBlocker`, and the model-refresh worker double exposes a `connect`.
- The block-width gates compared against `max(MIN, len*7 + padding)`, which
  equals the metric width under the offscreen 7px fallback font; they now compare
  against the raw `len*7` the pre-fix code used.
- The encoding harness now exposes a bound `_selected_search_encoding` so the
  borrowed `_replace_encoding` can chain through `self`.

Pre-existing, unrelated: `test_ui_mainwindow.py::TestOrphanSignalWiringRuntime::
test_session_loaded_signal_reaches_slot` hangs in the offscreen sandbox because
its session-load emission triggers an async error whose `_on_async_error`
(`app.py:1513`, untouched by this work) opens an unguarded `QMessageBox.critical`.
This is not a GUI-audit finding and not a regression from these changes (the diff
does not touch the session-load path); the M2/F-0026 gates in that file were
validated with `-k RefreshSystemStatus`.

## Notes on repository state

- All fixes live in the intended UI fileset plus their test gates. A tree-wide
  `ruff --fix` (run by an agent) and pre-existing uncommitted edits to
  non-Python config files (`.github/`, `.agents/`, `.opencode/`,
  `.claude/settings.local.json`) were left untouched and are **not** part of the
  audit commits; only the audit-relevant files were staged.
