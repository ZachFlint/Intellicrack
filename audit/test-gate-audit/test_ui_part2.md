# Test-Gate Audit — test_ui (part 2 + log_viewer)

## Summary
- Files audited: 25
- Test functions examined: 287
- Genuine gates: 261
- Flagged non-gates: 26  (CRITICAL: 12, HIGH: 1, MEDIUM: 13, LOW: 0)

## Coverage checklist
- [x] tests/test_ui/test_realcov_15_resource_url_dispatch.py — gates: 1, flagged: 0
- [x] tests/test_ui/test_realcov_15_session_manager_dialog.py — gates: 3, flagged: 0
- [x] tests/test_ui/test_resource_helper.py — gates: 25, flagged: 1
- [x] tests/test_ui/test_sandbox_panel_fixes.py — gates: 13, flagged: 0
- [x] tests/test_ui/test_search_async.py — gates: 6, flagged: 0
- [x] tests/test_ui/test_splash_screen.py — gates: 60, flagged: 6
- [x] tests/test_ui/test_state_persistence.py — gates: 11, flagged: 0
- [x] tests/test_ui/test_theme_manager.py — gates: 49, flagged: 0
- [x] tests/test_ui/test_tool_panel_detach.py — gates: 15, flagged: 0
- [x] tests/test_ui/test_tool_status_dialog_prefetch.py — gates: 4, flagged: 0
- [x] tests/test_ui/test_tools_logic.py — gates: 18, flagged: 0
- [x] tests/test_ui/test_vnc_widget.py — gates: 22, flagged: 11
- [x] tests/test_ui/test_win32_embed.py — gates: 6, flagged: 5
- [x] tests/test_ui/test_xpu_status.py — gates: 49, flagged: 1
- [x] tests/test_ui/log_viewer/__init__.py — gates: 0, flagged: 0 (no tests)
- [x] tests/test_ui/log_viewer/conftest.py — gates: 0, flagged: 0 (fixtures only)
- [x] tests/test_ui/log_viewer/test_record.py — gates: 11, flagged: 0
- [x] tests/test_ui/log_viewer/test_app_integration.py — gates: 3, flagged: 0
- [x] tests/test_ui/log_viewer/test_handler.py — gates: 5, flagged: 0
- [x] tests/test_ui/log_viewer/test_model.py — gates: 13, flagged: 0
- [x] tests/test_ui/log_viewer/test_proxy.py — gates: 10, flagged: 0
- [x] tests/test_ui/log_viewer/test_tail_reader.py — gates: 5, flagged: 0
- [x] tests/test_ui/log_viewer/test_realcov_15_tail_reader_real_logs.py — gates: 2, flagged: 0
- [x] tests/test_ui/log_viewer/test_window.py — gates: 24, flagged: 0
- [x] tests/test_ui/log_viewer/test_realcov_15_window_real_logs.py — gates: 2, flagged: 0

## Flagged tests

### tests/test_ui/test_resource_helper.py
#### `test_returns_false_for_empty_path` — MEDIUM — existence-only (N8)
- **Location:** tests/test_ui/test_resource_helper.py:234
- **Current behavior:** Calls `resource_exists("")` and asserts only `isinstance(result, bool)`.
- **Why it is not a gate:** The docstring claims "Handles empty path gracefully" but the assertion only checks the return type. A regression that returns `True` for an empty path (a real defect — empty path should not match a resource) would still pass because `True` is a `bool`. The other two tests in this class assert the actual truth value; this one does not.
- **Recommended fix:** Assert the value: `assert resource_exists("") is False` (an empty path is not an existing resource).

### tests/test_ui/test_splash_screen.py
#### `test_creates_splash_screen` — MEDIUM — existence-only (N8)
- **Location:** tests/test_ui/test_splash_screen.py:104
- **Current behavior:** Constructs `SplashScreen()` and asserts `splash is not None`.
- **Why it is not a gate:** A freshly constructed object can never be `None`; the constructor would raise before the assertion if it failed. This is the canonical `assert r is not None where r cannot be None` case. Construction is already exercised (with real assertions) by `test_splash_has_pixmap`, `test_initial_progress_is_zero`, etc.
- **Recommended fix:** Either delete (construction is covered by stronger tests) or assert an observable post-construction invariant, e.g. `assert splash.progress == 0` and `assert not splash.pixmap().isNull()`.

#### `test_rapid_progress_calls_no_error` — MEDIUM — no-assert (N1)
- **Location:** tests/test_ui/test_splash_screen.py:709
- **Current behavior:** Loops `set_progress(i)` for i in 0..100 step 5 and makes no assertion.
- **Why it is not a gate:** "Don't raise" with no assertion. If `set_progress` silently stopped updating state under rapid calls, the test stays green. The file's own `test_splash_screen_no_exceptions_on_operations` was explicitly hardened away from this exact anti-pattern; this test was left behind.
- **Recommended fix:** After the loop assert the final observable state, e.g. `assert splash_screen.progress == _PROGRESS_100` and that the animation end value tracks the last call.

#### `test_paint_event_no_crash` — MEDIUM — no-assert (N1)
- **Location:** tests/test_ui/test_splash_screen.py:937
- **Current behavior:** Shows the splash, calls `repaint()`, closes. No assertion.
- **Why it is not a gate:** Pure smoke test — a paint handler that drew nothing (or skipped a layer) would still pass. `repaint()` swallows paint-event exceptions inside Qt in many configurations, so even a raising handler may not surface here.
- **Recommended fix:** Render the paint sub-routines into a `QPixmap` (as `test_rendering_at_every_progress_step` does) and assert the pixmap is non-null / has expected non-background pixels, or at minimum assert post-paint widget state.

#### `test_paint_with_progress` — MEDIUM — no-assert (N1)
- **Location:** tests/test_ui/test_splash_screen.py:950
- **Current behavior:** Sets progress, repaints, closes. No assertion.
- **Why it is not a gate:** Same as above — no observable outcome is checked, so no paint regression can fail it.
- **Recommended fix:** Drive the real draw helpers onto a `QPainter`/`QPixmap` and assert a concrete render result, or assert state (`splash.progress == 50`).

#### `test_paint_full_pipeline` — MEDIUM — no-assert (N1)
- **Location:** tests/test_ui/test_splash_screen.py:963
- **Current behavior:** Sets progress to 100, repaints, closes. No assertion.
- **Why it is not a gate:** No assertion; same N1 reasoning. The stronger `test_failed_stage_renders_through_full_sequence` already proves the pipeline render path with assertions, making this redundant and non-gating.
- **Recommended fix:** Assert pipeline stage states after `set_progress(100)` (all COMPLETE) plus a non-null rendered pixmap.

#### `test_splash_image_loaded` — MEDIUM — vacuously-satisfiable conditional (N6)
- **Location:** tests/test_ui/test_splash_screen.py:1005
- **Current behavior:** Branches on `_brain_icon` and `splash_path.exists()`; in each branch asserts `_splash_image is None` or `is not None`.
- **Why it is not a gate:** The branch structure mirrors the production code's own loading logic (re-derives the expected outcome from the same conditions the implementation uses), so it is partly tautological (N10) and, more importantly, the branch actually taken on this machine is environment-dependent. The asset is known to ship (`test_splash_image_exists` asserts `splash.png` is present), so the meaningful branch (`_splash_image is not None`) should be asserted unconditionally rather than guarded.
- **Recommended fix:** Since `splash.png` is a committed asset, assert the loaded-image branch directly without the `if/elif` ladder, or independently fix the brain-icon precedence and assert the single correct outcome.

### tests/test_ui/test_vnc_widget.py
#### `test_pointer_event_format` — CRITICAL — tautological (N4/N10)
- **Location:** tests/test_ui/test_vnc_widget.py:135
- **Current behavior:** Packs a message with `struct.pack` inside the test and unpacks it with `struct.unpack`, asserting the round-trip.
- **Why it is not a gate:** No Intellicrack production code is invoked. It tests the Python `struct` module, not `RFBClient.send_pointer_event`. If the bridge's real packing logic were deleted, this test stays green.
- **Recommended fix:** Capture the bytes the real `send_pointer_event` writes to the connected stream (inject a real in-memory `asyncio.StreamWriter`/transport) and assert the on-wire bytes match the RFB spec.

#### `test_key_event_format` — CRITICAL — tautological (N4/N10)
- **Location:** tests/test_ui/test_vnc_widget.py:146
- **Current behavior:** `struct.pack` then `struct.unpack` entirely within the test; asserts the round-trip.
- **Why it is not a gate:** Tests `struct`, not the production `send_key_event` encoder. Deleting the real encoder leaves this green.
- **Recommended fix:** Assert the bytes produced by the real `send_key_event` against the RFB spec via an injected writer.

#### `test_framebuffer_update_request_format` — CRITICAL — tautological (N4/N10)
- **Location:** tests/test_ui/test_vnc_widget.py:157
- **Current behavior:** `struct.pack`/`struct.unpack` round-trip in the test; no production call.
- **Why it is not a gate:** Validates `struct` rather than `request_framebuffer_update`. Production regression cannot fail it.
- **Recommended fix:** Assert the bytes the real `request_framebuffer_update` emits to an injected writer.

#### `test_request_framebuffer_update_when_disconnected` — CRITICAL — no-assert (N1)
- **Location:** tests/test_ui/test_vnc_widget.py:118
- **Current behavior:** Calls `request_framebuffer_update()` on a disconnected client; no assertion.
- **Why it is not a gate:** "No-op when disconnected" is asserted by nothing. The method early-returns; whether it actually sent data or not is never observed. A regression that sent bytes despite being disconnected would pass.
- **Recommended fix:** Inject a recording writer and assert nothing was written while disconnected.

#### `test_send_pointer_when_disconnected` — CRITICAL — no-assert (N1)
- **Location:** tests/test_ui/test_vnc_widget.py:176
- **Current behavior:** Calls `send_pointer_event(...)` disconnected; no assertion.
- **Why it is not a gate:** No observable outcome checked; cannot fail on regression.
- **Recommended fix:** Assert no bytes were written to an injected writer when disconnected.

#### `test_send_key_when_disconnected` — CRITICAL — no-assert (N1)
- **Location:** tests/test_ui/test_vnc_widget.py:181
- **Current behavior:** Calls `send_key_event(...)` disconnected; no assertion.
- **Why it is not a gate:** Same as above — no side effect verified.
- **Recommended fix:** Assert no write occurred via an injected writer.

#### `test_apply_raw_rect_partial_data` — CRITICAL — no-assert (N1)
- **Location:** tests/test_ui/test_vnc_widget.py:206
- **Current behavior:** Fills a 4x4 framebuffer, calls `apply_raw_rect` with truncated pixel data; makes no assertion.
- **Why it is not a gate:** The docstring claims it "handles truncated pixel data" but nothing is asserted about the resulting framebuffer (which pixels were written, which were untouched, no crash-state). A regression that corrupted memory or wrote wrong pixels on short data would pass.
- **Recommended fix:** Assert the pixels covered by the partial data hold the decoded color and the remaining pixels retain the fill color (and no exception is raised).

#### `test_apply_raw_rect_no_framebuffer` — CRITICAL — no-assert (N1)
- **Location:** tests/test_ui/test_vnc_widget.py:217
- **Current behavior:** Calls `apply_raw_rect` with `framebuffer is None`; no assertion.
- **Why it is not a gate:** "No-op without framebuffer" is verified by nothing; the client's `framebuffer` stays `None` trivially regardless of behavior.
- **Recommended fix:** Assert `client.framebuffer is None` after the call (proving no framebuffer was allocated) — minimal, but at least observes the contract.

#### `test_construction` — MEDIUM — existence-only (N8)
- **Location:** tests/test_ui/test_vnc_widget.py:296
- **Current behavior:** Constructs `VNCWidget` and asserts only minimum width/height. (Acceptable as a weak gate, but the docstring says "can be constructed".)
- **Why it is not a gate (weak):** Asserts only size hints, not that the widget is functionally wired. Borderline; minimum-size is a real (if trivial) constraint. Counted as flagged because the assertion does not match the stated intent ("constructed") and only gates a layout constant.
- **Recommended fix:** Keep the size assertions but add an observable wiring check (e.g. `widget.client is not None and not widget.client.connected`), which the sibling `test_initial_client_disconnected` already covers — consider merging.

#### `test_button_mask_static_method_exists` — MEDIUM — existence-only (N8)
- **Location:** tests/test_ui/test_vnc_widget.py:355
- **Current behavior:** Asserts `callable(VNCWidget.button_mask)`.
- **Why it is not a gate:** Only checks the symbol is callable; a `button_mask` that returns the wrong mask for every Qt button would pass. The behavior (Qt button -> RFB button-mask mapping) is the thing that matters and is untested.
- **Recommended fix:** Call `VNCWidget.button_mask(...)` with known Qt mouse-button inputs and assert the exact RFB bitmask values.

### tests/test_ui/test_win32_embed.py
#### `test_returns_int_or_none_for_current_pid` — HIGH — accepts-both-outcomes (N7)
- **Location:** tests/test_ui/test_win32_embed.py:58
- **Current behavior:** Calls `find_window_by_pid(os.getpid())` and asserts `result is None or isinstance(result, int)`.
- **Why it is not a gate:** The assertion is satisfied by both possible outcomes (`None` OR any `int`). A `find_window_by_pid` that always returned `None` (the function fully broken) passes identically to one that works. No real defect in the lookup can fail this.
- **Recommended fix:** Create a real top-level `QWidget`, `show()` it, pump events, then assert `find_window_by_pid(os.getpid())` returns a non-`None` int that resolves back to a window belonging to the current process — making the success outcome mandatory.

#### `test_ctypes_windll_available` — MEDIUM — existence-only (N8)
- **Location:** tests/test_ui/test_win32_embed.py:65
- **Current behavior:** Asserts `hasattr(ctypes, "windll")`.
- **Why it is not a gate:** Tests the Python/Windows runtime, not Intellicrack's embedding code. `ctypes.windll` existing says nothing about whether `win32_embed` uses it correctly.
- **Recommended fix:** Remove, or fold into a real embedding test that exercises the Win32 path end-to-end.

#### `test_returns_widget_or_none_for_zero_hwnd` — MEDIUM — accepts-both-outcomes (N7)
- **Location:** tests/test_ui/test_win32_embed.py:81
- **Current behavior:** `embed_window(0, parent)`; asserts `result is None or isinstance(result, QWidget)`.
- **Why it is not a gate:** Both outcomes pass. The correct contract for an invalid (zero) HWND is presumably `None`; a regression that wrapped a garbage window and returned a `QWidget` would pass.
- **Recommended fix:** Assert the specific expected outcome for a zero handle: `assert embed_window(0, parent) is None`.

#### `test_returns_widget_or_none_for_garbage_hwnd` — MEDIUM — accepts-both-outcomes (N7)
- **Location:** tests/test_ui/test_win32_embed.py:88
- **Current behavior:** `embed_window(0xDEADBEEF, parent)`; asserts `None or isinstance(..., QWidget)`.
- **Why it is not a gate:** Both outcomes accepted; a bogus handle that erroneously embedded would still pass.
- **Recommended fix:** Assert the defined contract for a bogus handle (`is None`).

#### `test_accepts_callable_callback` — MEDIUM — no-assert (N1)
- **Location:** tests/test_ui/test_win32_embed.py:150
- **Current behavior:** Calls `poll_and_embed(...)` with a no-op callback; makes no assertion and does not pump the event loop.
- **Why it is not a gate:** Nothing is observed. It only confirms `poll_and_embed` does not raise synchronously at call time; the polling lifecycle is never driven or checked. A broken poller passes.
- **Recommended fix:** Either delete (the lifecycle is covered by `test_callback_not_called_for_missing_pid` and `test_max_retries_limits_attempts`) or pump the timer and assert the callback was/was not invoked as required.

### tests/test_ui/test_xpu_status.py
#### `test_memory_text_shows_gb_values` — MEDIUM — log/string-presence proxy (N9)
- **Location:** tests/test_ui/test_xpu_status.py:397
- **Current behavior:** (XPU-gated) asserts only that the memory text contains the substrings `"GB"` and `"%"`.
- **Why it is not a gate:** Checks for literal marker substrings, not the actual numeric correctness of the rendered allocated/total GB or percentage. A regression that printed `"0.0 GB / 0.0 GB (NaN%)"` or swapped allocated/total would still contain `"GB"` and `"%"` and pass. The sibling `test_memory_bar_shows_real_percentage` already asserts the real computed value, so the bar is gated but this text is not.
- **Recommended fix:** Reconstruct the expected GB strings from `get_xpu_memory_info(0)` and assert the formatted numbers (allocated/total/percent) appear with their correct values, not just the unit markers.

## Acceptable skips (not flagged)
- tests/test_ui/test_win32_embed.py:57 `test_returns_int_or_none_for_current_pid` — `skipif(sys.platform != "win32")` is a legitimate OS-capability gate (Win32 window API is Windows-only); the skip itself is acceptable. The test is flagged for its accepts-both-outcomes assertion, not the skip.
- tests/test_ui/test_win32_embed.py:64 `test_ctypes_windll_available` — `skipif(sys.platform != "win32")` legitimate (ctypes.windll is Windows-only).
- tests/test_ui/test_xpu_status.py:297,309,330 (device-name/driver/capabilities) — `skipif(not is_xpu_available())` is a legitimate hardware-capability skip (no Intel XPU present in the runner); when hardware is present each asserts an exact oracle-derived value, so the capability is hard-gated where it can run.
- tests/test_ui/test_xpu_status.py:366,396 (memory bar / memory text) — `skipif(not is_xpu_available())` legitimate hardware skip; `test_memory_bar_shows_real_percentage` gates the real value when present (the text variant is flagged separately above).
- tests/test_ui/test_xpu_status.py:408 `test_memory_shows_no_device_when_unavailable` — `skipif(is_xpu_available())` legitimate inverse hardware gate; asserts the exact `"No XPU device"` string on the no-device path.
- tests/test_ui/test_realcov_15_resource_url_dispatch.py:112 — registering a real in-process `QDesktopServices` URL handler (rather than launching a browser) is the standard, legitimate test seam; it exercises the real `openUrl` dispatch and asserts the routed URL, so it is a genuine gate, not a mask.
- tests/test_ui/test_tool_status_dialog_prefetch.py:139 — monkeypatching `ToolStatusCheckWorker.start` is a legitimate determinism control (prevents real OS threads) used only as a spawn counter; the rendered rows and counts are asserted against an independent oracle, so the behavior under test (prefetch reuse vs spawn) is genuinely gated.
- tests/test_ui/log_viewer/test_handler.py:199 — monkeypatching `from_logging_record` to raise is the only way to deterministically exercise the `handleError` failure path; the captured `LogRecord` identity is asserted, so it remains a genuine gate.
