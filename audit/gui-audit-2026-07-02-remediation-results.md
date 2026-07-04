# GUI Audit 2026-07-02 — Gate-Test Remediation Results

This document records the remediation of the **18 gate-test files** that did
not pass in the Docker sandbox after the initial 2026-07-02 GUI audit fixes
were applied. Each of the 131 audit findings already had a source fix and a
falsifiable gate test on disk; this pass drove those gate tests to green in the
sandbox by fixing (a) genuinely incomplete/incorrect **source** fixes, (b)
**test-harness** defects that masked or blocked the real behaviour, and (c) a
shared **worker-teardown** lifecycle gap in the async-bridge machinery.

All verification runs use the Docker sandbox
(`scripts.sandbox.docker_sandbox custom`, offscreen Qt, per-file isolation).
Every changed file passes `ruff`, `basedpyright`, `pydoclint`, and `pydocstyle`
with zero findings and zero suppressions.

## Shared production fix — async-bridge worker drain

`main.py:_shutdown_application` stopped the persistent bridge event loop
(`shutdown_bridge_loop`) **without first draining** the in-flight
`BridgeCallWorker` / `GenericCallableWorker` `QThread` instances retained in
`_WorkerRegistry`. A worker whose OS thread is still running when the loop it
awaits is stopped — or when its owning widget is destroyed — is torn down
mid-flight, aborting the process with `QThread: Destroyed while thread is still
running` (Windows access violation, exit 255).

- **`async_bridge.py`**: added the public `drain_bridge_workers(timeout_ms)`
  helper that blocks until every retained worker thread has finished.
- **`main.py`**: `_shutdown_application` now calls `_drain_and_stop_bridge_loop`,
  which drains workers before `shutdown_bridge_loop`.
- **`tests/test_ui/conftest.py`**: the session `qapp` fixture now drains
  workers, flushes `DeferredDelete` events, and stops the bridge loop on
  teardown; a new function-scoped autouse fixture drains workers after every UI
  test so no worker outlives the objects it references.

Falsifiable check: `provider_config` (a real `ModelRefreshWorker` refresh) went
from a hard exit-255 crash to a clean pass solely from this drain.

### Direct gate coverage for the drain (product path, not just the test suite)

The drain was initially proven only *indirectly* (via `provider_config`). It now
has dedicated falsifiable gates that exercise the production shutdown path with a
real `BridgeCallWorker` running a live coroutine on the persistent bridge loop:

- **`tests/test_ui/test_async_bridge.py::TestDrainBridgeWorkers`** — asserts
  `drain_bridge_workers` blocks until a genuinely in-flight worker thread has
  finished (`not worker.isRunning()` afterwards) and counts already-finished
  workers.
- **`tests/test_core/test_main.py::TestBridgeLoopShutdownDrain`** — drives the
  real `intellicrack.main._drain_and_stop_bridge_loop` helper called from
  `_shutdown_application`: a worker mid-`asyncio.sleep` on the bridge loop must be
  drained (finished) *before* the loop is stopped, and the loop must then be
  stopped (`loop.is_running()` is `False`).

Falsifiability verified by regression injection: neutering
`drain_bridge_workers` to a no-op turns **all three** gates red (worker still
running after the call; loop torn down mid-flight), then reverting restores green
(combined `34 passed`). This is the falsification signal required of a real gate:
without the drain, the worker's blocking `future.result()` never returns once the
loop it awaits is stopped, so `isRunning()` stays `True` and the shutdown-crash
precondition is present.

## Source fixes (incomplete/incorrect audit fixes, now completed)

| Finding | File | Root cause | Fix |
|---|---|---|---|
| **H8** | `hex_editor/transforms.py` | `_on_apply_arithmetic` still made **two blocking** `run_bridge_coroutine` calls on the GUI thread and never imported `run_bridge_coroutine_logged`. | Dispatch a single chained coroutine (`select_range` → `apply_arithmetic_to_selection`) via `run_bridge_coroutine_logged` (`event="hex_editor_apply_arithmetic"`), refreshing the widget from the success callback and warning from the error callback. |
| **M2** | `log_viewer/_tail_reader.py` | `stop()` disconnected signals on an already-deleted `InitialLoadWorker`; `contextlib.suppress(TypeError)` did not catch the `RuntimeError` raised for a deleted C/C++ object, so closing the log viewer after the initial load crashed in `closeEvent`. | Broadened the worker-disconnect guards to `suppress(TypeError, RuntimeError)`. |
| **L2** | `resources/font_manager.py` | `get_heading_font` read `_config_font_size("ui_large", 12)` **before** the font config was loaded (missing the `load_fonts()` guard its siblings have), so it always returned the hardcoded default. | Added the `if not self.fonts_loaded: self.load_fonts()` guard so the configured `ui_large` size is honoured. |

## Test-harness fixes (source correct; gate defect corrected without weakening it)

| Finding | File | Root cause | Fix |
|---|---|---|---|
| **H1** | `app` | `patched_window` stubs `SandboxManager`→`NoOpSandboxManager`; the rebuild in `_finish_sandbox_settings_apply` then produced a NoOp, failing `isinstance(..., SandboxManager)`. | Restore the real `SandboxManager` on the module before triggering apply. |
| **C2** | `panels_hex_editor_panel` | Asserted the full rule id in the list item, but the source deliberately renders `rule_id[:8]`. | Assert `str(rule["id"])[:8]` (matches the intentional truncation). |
| **M7** | `panels_hex_editor_patches` | Pump predicate raced on a background-thread document write instead of the GUI-thread dialog callback. | Pump on `dialogs.calls`; keep the document mutation as a post-condition. |
| **H32** | `panels_hex_editor_scripting` | Read token colours from `cursor.charFormat()`, which never reflects `QSyntaxHighlighter` overlays. | Flush `rehighlight()` and read the applied format from `block.layout().formats()`. |
| **H7** | `panels_hex_editor_search` | Pump predicate raced on the document write instead of the GUI-thread status label. | Pump on the `_search_status_label` text; assert document contents after. |
| **M54/L12** | `panels_hex_editor_signatures` | `_SignaturesHost` (a plain object) discarded the `QWidget` container from `_create_signatures_tab()`, so GC deleted its child label/tree → dangling wrappers. Also `heightForWidth` does not compute wrapped height for an unshown label offscreen. | Added `build_tab()` retaining the container; measure wrap height via `QFontMetrics.boundingRect(..., TextWordWrap)` on the label's font. |
| **H9** | `panels_hex_editor_widget` | The entropy rescan is gated on `minimap.isVisible()`, but the test never showed the widget. | `widget.show()` + `processEvents()` before arming the minimap (matches sibling tests). |
| **H11** | `panels_sandbox_panel` | Asserted `stop_pcap` dispatch synchronously without pumping for the async worker. | Poll for `stop_pcap_calls` (mirrors the existing `destroy_calls` poll). |
| **L14** | `panels_script_manager` | `visualItemRect().width()` returns the item's content width, never the clamped viewport, so the elision premise could not hold. | Fix the list to a narrow width and compare against `viewport().width()`. |
| **H28/M65** | `panels_x64dbg_panel` | H28 expected the stale `"Not loaded"` (the wired base-class label correctly shows `"No bridge configured"`); M65 required strictly >2 lines when a genuine 2-line wrap is correct. | Expect `"No bridge configured"`; require wrap height `> line_height` (≥2 lines). |
| **M4/M5** | `panels_hex_editor_data_inspector` | `qtbot.waitUntil(widget._encode_output.text, ...)` passed a callback returning a **string** (pytest-qt requires bool/None → `ValueError`), and the early error left the worker to touch the deleted label at teardown. | Wrap the callback: `lambda: bool(widget._encode_output.text())`. |
| **H4** | `panels_hex_editor_export_report` | Export success/error callbacks report via modal `show_info`/`show_warning`; driven synchronously offscreen, the modal's nested loop never returns → hang. | Autouse fixture makes `QMessageBox.information`/`warning` non-blocking. |
| **H6** | `panels_hex_editor_highlighting` | Pumping the event loop fired a debounced follow-cursor disassembly that showed a modal `QMessageBox.warning`, hanging the offscreen loop. | Autouse fixture makes `QMessageBox.warning` non-blocking (the warning-asserting test overrides it). |
| **H12/L3** | `panels_vnc_widget` | `test_h12_disconnect_is_non_blocking` dispatched a real 2.5 s `BridgeCallWorker` (`parent=widget`) then returned without waiting; the widget was deallocated on return, destroying its still-running `QThread` child → exit 255. | Drain the worker (bounded pump) and `deleteLater` the widget in `finally` so no worker outlives it. |

## Verification

Per-file sandbox status (exit 0 = pass). All 18 previously-failing gate files
now pass:

| # | File | Prior | Now |
|---|---|---|---|
| 1 | `test_gui_audit0702_app.py` | exit 1 | **PASS** |
| 2 | `test_gui_audit0702_log_viewer_window.py` | exit 1 | **PASS** |
| 3 | `test_gui_audit0702_panels_hex_editor_panel.py` | exit 1 | **PASS** |
| 4 | `test_gui_audit0702_panels_hex_editor_patches.py` | exit 1 | **PASS** |
| 5 | `test_gui_audit0702_panels_hex_editor_scripting.py` | exit 1 | **PASS** |
| 6 | `test_gui_audit0702_panels_hex_editor_search.py` | exit 1 | **PASS** |
| 7 | `test_gui_audit0702_panels_hex_editor_signatures.py` | exit 1 | **PASS** |
| 8 | `test_gui_audit0702_panels_hex_editor_transforms.py` | exit 1 | **PASS** |
| 9 | `test_gui_audit0702_panels_hex_editor_widget.py` | exit 1 | **PASS** |
| 10 | `test_gui_audit0702_panels_sandbox_panel.py` | exit 1 | **PASS** |
| 11 | `test_gui_audit0702_panels_script_manager.py` | exit 1 | **PASS** |
| 12 | `test_gui_audit0702_panels_x64dbg_panel.py` | exit 1 | **PASS** |
| 13 | `test_gui_audit0702_provider_config.py` | exit 255 (crash) | **PASS** |
| 14 | `test_gui_audit0702_resources_font_manager.py` | exit 1 | **PASS** |
| 15 | `test_gui_audit0702_panels_hex_editor_data_inspector.py` | exit 255 (crash) | **PASS** |
| 16 | `test_gui_audit0702_panels_vnc_widget.py` | exit 255 (crash) | **PASS** |
| 17 | `test_gui_audit0702_panels_hex_editor_export_report.py` | exit 124 (hang) | **PASS** |
| 18 | `test_gui_audit0702_panels_hex_editor_highlighting.py` | exit 124 (hang) | **PASS** |
