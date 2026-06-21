# Test-Gate Audit — test_audit4 (group 2: modules/system tabs + hex wiring c1-c7)

## Summary
- Files audited: 15 (3 conftest/fixture files + 12 test modules; 10 `__init__.py` empty markers not counted)
- Test functions examined: 86
- Genuine gates: 79
- Flagged non-gates: 7  (CRITICAL: 1, HIGH: 0, MEDIUM: 6, LOW: 0)

## Coverage checklist
- [x] b5_modules_tab/conftest.py — fixtures only, gates: 0, flagged: 0
- [x] b5_modules_tab/test_modules_tab.py — gates: 9, flagged: 0
- [x] b5_modules_tab/test_realcov_14a_modules_tab.py — gates: 3, flagged: 0
- [x] b6_system_tab/conftest.py — WarningRecorder + 2 self-tests, gates: 2, flagged: 0
- [x] b6_system_tab/test_system_tab.py — gates: 13, flagged: 0
- [x] b6_system_tab/test_realcov_14a_system_tab.py — gates: 3, flagged: 0
- [x] b7_process_panel_workers/test_tracked_refresh_worker.py — gates: 4, flagged: 0
- [x] c1_hex_search_wiring/test_search_wiring.py — gates: 8, flagged: 1
- [x] c2_hex_highlighting_route/test_highlighting_route.py — gates: 13, flagged: 0
- [x] c2_hex_highlighting_route/test_realcov_13b_highlight_apply.py — gates: 5, flagged: 0
- [x] c3_hex_data_inspector/test_data_inspector.py — gates: 14, flagged: 0
- [x] c4_hex_transforms_notify/test_transforms_notify.py — gates: 13, flagged: 0
- [x] c5_hex_templates_pattern/test_templates_pattern.py — gates: 11, flagged: 0
- [x] c6_hex_hashing/test_hashing.py — gates: 13, flagged: 0
- [x] c7_hex_bookmarks_notify/test_bookmark_notify.py — gates: 7, flagged: 5

## Flagged tests

### c7_hex_bookmarks_notify/test_bookmark_notify.py

The five "add bookmark" tests below share one structural defect: the harness method
`add_bookmark_direct` (lines 158-173) does **not** invoke the production handler
`_on_add_bookmark`. Instead the harness itself calls `self.document.add_bookmark(...)`,
then directly calls `self.notify_data_modified_for_test(offset, length,
source="hex-editor.bookmarks.add")` (line 172), passing the offset, length, AND the
source literal that the production code in `bookmarks.py:93` is supposed to supply.
Because the test supplies those exact values, the assertions verify the test harness,
not the production `_on_add_bookmark` body. If `_on_add_bookmark` were deleted, mis-wired
to omit the notify, or changed to pass a wrong offset/source, these tests would still pass
because they never call `_on_add_bookmark` (they reconstruct its post-dialog tail by hand).
This is N10 (self-fulfilling data) / N1-adjacent for the production handler under test.

By contrast the *remove* tests in `TestRemoveBookmarkNotifies` genuinely call
`_on_remove_bookmark` (via `remove_bookmark_for_test`, line 205) and read offset/length back
from `document.list_bookmarks()`, so they are real gates and are NOT flagged.

#### `test_add_bookmark_publishes_data_modified` — MEDIUM — N10
- **Location:** c7_hex_bookmarks_notify/test_bookmark_notify.py:213
- **Current behavior:** Calls `add_bookmark_direct`, which fires the notify by hand, then asserts one DATA_MODIFIED event.
- **Why it is not a gate:** The notify is issued by the test harness (line 172), not by `_on_add_bookmark`. Deleting or breaking the production notify call in `_on_add_bookmark` would not turn this red because `_on_add_bookmark` is never executed.
- **Recommended fix:** Drive the real `_on_add_bookmark` by monkeypatching `QInputDialog.getText`/`QColorDialog.getColor` to return accepted values (the dialog seam), then assert the event. The handler — not the harness — must originate the notify.

#### `test_add_bookmark_offset_and_length_match_bookmark` — MEDIUM — N10
- **Location:** c7_hex_bookmarks_notify/test_bookmark_notify.py:230
- **Current behavior:** Asserts payload offset/length equal `_BM_OFFSET`/`_BM_LENGTH`.
- **Why it is not a gate:** Those exact values were handed to `notify_data_modified_for_test` by the harness on line 172; the production handler (which derives offset from `_hex_widget._cursor_offset` and hardcodes length 1) is never run. A regression where `_on_add_bookmark` notifies with the wrong offset would not be caught.
- **Recommended fix:** Same as above — run `_on_add_bookmark` with a stub hex widget whose `_cursor_offset` is a known non-zero value and assert the payload matches that cursor offset and length 1.

#### `test_add_bookmark_source_literal_uses_bookmarks_namespace` — MEDIUM — N10
- **Location:** c7_hex_bookmarks_notify/test_bookmark_notify.py:250
- **Current behavior:** Asserts the source starts with `hex-editor.bookmarks.`.
- **Why it is not a gate:** The source literal is supplied by the test on line 172, not read from production. If `bookmarks.py:93` changed its source to `"panel"`, this test would still pass.
- **Recommended fix:** Run the real `_on_add_bookmark`; the source under assertion must be the one production passes.

#### `test_panel_loop_guarded_subscriber_receives_add_event` — MEDIUM — N10
- **Location:** c7_hex_bookmarks_notify/test_bookmark_notify.py:270
- **Current behavior:** Registers a `source_id="panel"` subscriber and asserts it receives the add DATA_MODIFIED.
- **Why it is not a gate:** The event it observes was emitted by the harness's hand-rolled notify (line 172), so it proves the loop guard does not filter `"panel"` against `"hex-editor.bookmarks.add"` — but it never proves `_on_add_bookmark` actually emits with that source. The production add path could be broken and this passes.
- **Recommended fix:** Drive `_on_add_bookmark` through the dialog seam so the observed event originates in production.

#### `test_add_bookmark_no_notify_when_state_holder_absent` — CRITICAL — N1
- **Location:** c7_hex_bookmarks_notify/test_bookmark_notify.py:296
- **Current behavior:** Builds a no-state harness, calls `document.add_bookmark` then the `_notify_state_data_modified` helper with `state_holder=None`. There is **no assertion at all** — it only checks that no exception is raised.
- **Why it is not a gate:** A no-assert test (N1) is always green regardless of behavior. Even the "degrades gracefully" claim is unverified: nothing asserts that no event fired or that the helper returned without side effects. The early `return` in `_notify_state_data_modified` (bookmarks.py:49-50) could be deleted and this test would still pass as long as the subsequent `getattr` did not raise.
- **Recommended fix:** Register a recording subscriber on a real state holder is not possible here (state_holder is None by design); instead assert the call returns `None` and, more importantly, attach a state holder spy whose `notify_data_modified` raises if called, proving the `None` guard short-circuits. Add a concrete assertion.

## Acceptable skips (not flagged)
- c7_hex_bookmarks_notify/test_bookmark_notify.py:45 `pytest.importorskip("intellicrack_hexcore")` — module-level skip when the native Rust hexcore extension is not built. This is a legitimate environment-capability skip (missing compiled native dependency), not a skip masking the behavior under test; the bookmark notify logic genuinely requires the real `HexDocument`.
- b5_modules_tab/test_realcov_14a_modules_tab.py:65, b6_system_tab/test_realcov_14a_system_tab.py:64 `require_windows()` — these real-coverage tests attach a live `ProcessBridge` to the running process and enumerate genuine Win32 modules/token privileges; the Windows gate is a legitimate OS-capability skip on non-Windows runners. The assertions (ntdll/kernel32 present with non-zero bases, SeChangeNotifyPrivilege present, rendered values matching the real bridge enumeration) are strong real gates on Windows.

## Notes on near-misses that were NOT flagged

- **c1 `test_dead_class_annotation_removed` (search_wiring.py:294)** — asserts `_document` is
  absent from `SearchMixin.__annotations__`. This is an N8-style existence check, but it is a
  legitimate, falsifiable regression guard for the specific F-0001 root cause (the dead class
  annotation that shadowed `self.document`) and is paired with behavioral tests in the same
  class that drive `_on_search`. Counted as a (narrow) genuine gate, not flagged. The single
  flagged c1 entry is below.

### c1_hex_search_wiring/test_search_wiring.py
#### `test_search_no_attribute_error_when_document_set` — MEDIUM — N2/N4
- **Location:** c1_hex_search_wiring/test_search_wiring.py:245
- **Current behavior:** Wraps `mixin._on_search()` in `try/except AttributeError`, stores the caught exception, then asserts `raised is None`.
- **Why it is weak:** This is a "did not raise a specific exception" gate. The companion test `test_search_dispatches_worker_with_correct_document` already proves `_on_search` reaches `self.document` and builds a worker bound to the real document (a strictly stronger assertion). This test adds nothing the stronger test does not already cover, and an `AttributeError`-free run does not prove the search dispatched correctly — only that one exception type was avoided. Borderline N4 (asserting the absence of one error class as the sole behavioral claim).
- **Recommended fix:** Either delete it as redundant with the dispatch test, or strengthen it to assert the worker was created AND bound to `self.document` (i.e., fold it into the positive dispatch assertion) so the test gates the search actually running, not merely the absence of one exception.

## Stub/monkeypatch usage that is acceptable (not flagged)

Several files in this group use stubs/monkeypatches at the async-bridge dispatch seam
(`run_bridge_coroutine_async`, `run_bridge_coroutine_logged`) or at the Qt dialog seam
(`QMessageBox.question`, `_BlockFillDialog.exec`). These are NOT N5 mock-validates-mock because
the unit under test (the panel handler: `_on_pipe_close`, `_on_job_info`, `_refresh_*`,
`_on_block_fill`, `_on_repair_pe_checksum`, `_on_add_highlight_rule`, etc.) is the **real
production code** and the assertions check its genuine side effects (row kept/removed, tree
cleared, on_error wired, real PE checksum bytes written, real document bookmarks created, real
template registered/decoded). The stub sits at an external boundary (the background event loop or
a blocking modal), and the b6 conftest WarningRecorder deliberately drives the *real*
`QMessageBox.warning` modal rather than faking it. c5/c6 drive the real `intellicrack_hexcore`
document, real `HexPatCompiler`, real `HexPatInterpreter`, and cross-validate the PE checksum
against the independent `pefile.generate_checksum` oracle — strong real gates.
