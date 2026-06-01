# Agent 01 - Test Quality Audit

## Partition
- tests/test_audit4/b2_process_tab/conftest.py
- tests/test_audit4/b2_process_tab/test_process_tab.py
- tests/test_audit4/b4_memory_tab/test_memory_tab.py
- tests/test_audit4/b4_memory_tab/test_realcov_14a_memory_tab.py
- tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py
- tests/test_audit5/u7_ui_providerconfig/test_provider_specific_ui.py
- tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py
- tests/test_audit7/sandbox_monitors/conftest.py
- tests/test_audit7/sandbox_monitors/test_dll_log_parser.py
- tests/test_audit7/ui_panels_process/conftest.py
- tests/test_audit7/ui_panels_process/test_threads_auto_refresh.py
- tests/test_bridges/test_process_bridge.py
- tests/test_core/test_process_manager_audit6.py
- tests/test_credentials/test_env_loader_roundtrip_live.py
- tests/test_hexcore_e2e/test_bookmarks.py
- tests/test_hexcore_e2e/test_document_lifecycle.py
- tests/test_ui/log_viewer/test_realcov_15_tail_reader_real_logs.py

Total test functions audited: 308

## Findings

### tests/test_audit4/b2_process_tab/test_process_tab.py:207 - test_inject_warns_when_no_process_attached
- Violation(s): Mock-the-thing-under-test / Weak-assertion-on-rich-output
- Why it is not a real gate: The test patches `QMessageBox.warning` to capture calls, but only asserts that `len(warning_calls) > 0` — it never verifies (1) that the dialog content contains the correct message, (2) what the title text is, or (3) that the bridge was NOT invoked (proving the early guard worked). A production bug where the code calls warning twice, or calls it with the wrong message, would still pass this test.
- Severity: Medium
- Fix recommendation: Capture the warning call arguments and assert the exact title contains "Not Attached" and the message describes the problem of no attachment. Also verify that the bridge method is never called by patching `run_bridge_coroutine_async` and asserting it was not invoked.

### tests/test_audit4/b2_process_tab/test_process_tab.py:228 - test_inject_does_not_warn_when_attached
- Violation(s): Weak-assertion-on-rich-output / False confidence in negative check
- Why it is not a real gate: The test patches `QFileDialog.getOpenFileName` to return empty, but never verifies that the dialog was invoked at all (to prove the code reached the inject path). It only checks that the warning title does NOT contain "not attached", which is a very narrow gate. If the code is refactored to show a different warning instead, or to not warn at all, the test still passes.
- Severity: Medium
- Fix recommendation: Assert that the file dialog was shown (by checking `getOpenFileName` was called). Then verify either that no warning is shown at all, or that a specific non-"Not Attached" message is shown. Use a capture mock to verify the exact behavior.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:213 - test_on_read_no_dispatch_when_unattached
- Violation(s): Mock-the-thing-under-test / Insufficient verification of precondition guard
- Why it is not a real gate: The test manually sets `_attached_pid = None` and patches `run_bridge_coroutine_async`, then calls `_on_read()` and asserts the mock was not called. However, the test never verifies that the code actually checks `_attached_pid` before dispatch — it only verifies the empirical outcome. If the guard is removed or commented out, the test still passes as long as something else prevents the call (e.g., an exception in the dialog path). A real gate would call `_on_read()` with a real bridge and verify it surfaced an error dialog and did not execute the underlying operation.
- Severity: Medium
- Fix recommendation: Patch both `run_bridge_coroutine_async` (to fail if called) and `QMessageBox.warning` (to capture the warning). Verify the warning is shown with a message about needing attachment. Verify the bridge dispatch is skipped entirely by a guard check, not by some other control flow.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:232 - test_on_write_no_dispatch_when_unattached
- Violation(s): Mock-the-thing-under-test / Insufficient verification of precondition guard
- Why it is not a real gate: Same as test_on_read_no_dispatch_when_unattached — the test checks that the bridge is not called, but does not verify that the guard is explicitly checking `_attached_pid`. A refactored implementation that skips the write for any reason (e.g., invalid address parsing) would still pass.
- Severity: Medium
- Fix recommendation: Add a paired test where `_attached_pid` IS set, call `_on_write()`, and verify the dispatch proceeds. This demonstrates that the guard is specifically checking the attachment state and is not coincidentally skipped by other logic.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:252 - test_on_search_no_dispatch_when_unattached
- Violation(s): Mock-the-thing-under-test / Insufficient verification of precondition guard
- Why it is not a real gate: Same pattern as above — the test only verifies the bridge is not called, not that the code explicitly guards on `_attached_pid`. Production code that skips search for any reason would still pass.
- Severity: Medium
- Fix recommendation: Verify the guard explicitly by testing that a real search with `_attached_pid` set DOES dispatch, then test that the same search with `_attached_pid = None` is blocked. This pair of tests demonstrates the guard is the controlling factor.

### tests/test_audit4/b4_memory_tab/test_realcov_14a_memory_tab.py:195 - test_region_map_populated_from_real_memory_map
- Violation(s): Weak-assertion-on-rich-output / Insufficient structure validation
- Why it is not a real gate: The test calls `pump_until(qapp, lambda: tab.region_count() > 0)` and then asserts `rows >= 1`, `first_base` is not None, and the count label matches. However, it never validates that the base address and size values are _correctly_ parsed from the real memory map — it only checks they are not None and parse as hex. A bug where addresses are swapped, or sizes are halved, would not be caught. The test also does not verify that the specific modules expected to be in this process (e.g., ntdll, kernel32) are actually present.
- Severity: High
- Fix recommendation: After populating the region table, enumerate specific known module ranges (e.g., kernel32.dll's reported base from `get_modules`), and verify that each module's address range falls within a region in the table. This proves the table was actually populated from the real host, not just filled with placeholder data.

### tests/test_audit4/b4_memory_tab/test_realcov_14a_memory_tab.py:222 - test_region_map_contains_real_module_region
- Violation(s): Weak-assertion-on-rich-output / Insufficient validation of overlap semantics
- Why it is not a real gate: The test retrieves the ntdll base via `_ntdll_base()`, populates regions, and then checks `base <= ntdll_base < base + size`. However, it never verifies that the returned base and size are actually the REAL values — it only checks that ntdll falls within some region. A bug where region bases are off by a page, or sizes are wrong, would still pass as long as ntdll happens to fall within the range. The test also does not verify that the region it found is correctly marked with the expected protection flags or module name if the bridge provides that information.
- Severity: High
- Fix recommendation: After finding the region containing ntdll, verify its properties against the real `get_modules` output: the base should match (or be close to) ntdll's reported base, and the size should be >= ntdll's reported size. Check that the protection field (if available) includes execute permission for a code module.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:219 - test_region_filter_wired_to_text_changed
- Violation(s): No-assertion / Vacuous assertion / Coverage-theater
- Why it is not a real gate: The test sets up a table with two rows, then calls `tab._region_filter.insert("ntdll")` and checks that row 0 is not hidden and row 1 is hidden. However, the test does not explicitly verify that `textChanged` signal was connected and automatically triggered the filter callback — it only empirically checks the outcome. If the signal is not wired and the test manually calls the filter method elsewhere, the test still passes. A more direct test would verify that the signal is actually connected by checking the signal's receivers or by testing that changing text WITHOUT calling the filter method still hides the row.
- Severity: Low
- Fix recommendation: Use `qtbot.signalSpy` to capture `textChanged` emissions, or manually emit a signal and verify the filter is invoked. Alternatively, add a second assertion that if you change the filter text programmatically (via `setText` rather than `insert`) the row visibility still changes, proving the signal is wired.

### tests/test_audit5/u7_ui_providerconfig/test_provider_specific_ui.py:159 - test_resource_button_invokes_qdesktopservices
- Violation(s): Mock-the-thing-under-test / Insufficient assertion on button behavior
- Why it is not a real gate: The test patches `QDesktopServices.openUrl` and clicks buttons, then asserts `mock_open.called` and compares the called URL to the expected link. However, it never verifies that the button's clicked signal is actually connected to the resource-open handler — it only checks the empirical outcome. If the button is wired to a no-op handler instead, or if the button click does not actually fire, the test would fail differently. A real gate would verify that clicking the button triggers the URL open by inspecting the button's connections or by testing that a failure (openUrl returns False) is surfaced to the user.
- Severity: Medium
- Fix recommendation: Verify the button click actually invokes the handler by adding a second test where `openUrl` returns False and a warning is shown. This demonstrates the handler is wired and responds to button clicks. Alternatively, use `qtbot.signalSpy` to capture the clicked signal and verify it fires when the button is pressed.

### tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py:131 - test_available_types_are_a_subset_of_real_probes
- Violation(s): Weak-assertion-on-rich-output / Insufficient cross-validation
- Why it is not a real gate: The test calls `manager.get_available_types()` and then independently probes `WindowsSandbox` and `QEMUSandbox`. It asserts that reported types match the independent probes with `assert ("windows" in reported) == windows_real`. However, this assertion only checks the boolean equivalence, not that the implementation is actually calling the real probes — if the code fabricates availability and the host happens to have no sandboxes available, the test still passes. A more robust gate would verify the manager is making the real probe calls by injecting a failure (e.g., simulating a host without QEMU) and confirming the reported type changes accordingly.
- Severity: High
- Fix recommendation: Add a follow-up test that patches `QEMUSandbox.is_available` to raise an exception, call `get_available_types()`, and verify that "qemu" is NOT in the returned list (or that an error is surfaced). This proves the manager is calling the real is_available method and respecting its results.

### tests/test_audit7/ui_panels_process/test_threads_auto_refresh.py:217 - test_toggling_on_starts_timer_and_increments_call_count
- Violation(s): Weak-assertion-on-rich-output / Insufficient validation of polling interval
- Why it is not a real gate: The test turns on auto-refresh, waits 7000 ms, patches `run_bridge_coroutine_async` with a counter, and asserts `calls_after_on > 1`. However, this assertion only verifies that the callback was invoked more than once; it does not verify the interval is correct. If the interval is 1 ms instead of 3000 ms, the test would still pass (and pass even faster). The test also does not verify that the timer actually fired via Qt's event loop — it only checks the side effect of the mock being called.
- Severity: Medium
- Fix recommendation: Add a separate test (or extend this one) that measures the time between successive calls and verifies the interval is approximately 3000 ms (with some tolerance for Qt's scheduling granularity). Use `time.perf_counter()` or a clock mock to verify the interval is enforced by the timer.

### tests/test_bridges/test_process_bridge.py:516 - test_list_processes_non_empty
- Violation(s): Weak-assertion-on-rich-output / Insufficient validation of output shape
- Why it is not a real gate: The test asserts `len(procs) > 0`, which only verifies the list is non-empty. A bug where the list is populated with invalid or malformed ProcessInfo objects would not be caught. The test does not verify that the list contains valid ProcessInfo instances with required fields (pid, name, etc.) or that the returned data matches a known process running on the host.
- Severity: Low
- Fix recommendation: Extend the assertion to verify that at least one process in the list has a valid structure: `assert all(hasattr(p, 'pid') and hasattr(p, 'name') and p.pid > 0 for p in procs)`. Better: assert that the current process (Python) is in the list and has the expected PID.

### tests/test_bridges/test_process_bridge.py:545 - test_list_processes_filter
- Violation(s): Weak-assertion-on-rich-output / Insufficient assertion on filter semantics
- Why it is not a real gate: The test calls `list_processes(filter_name="python")` and asserts the result has at least 1 entry. However, it does not verify that the filter was actually applied — it only checks the result size. If the filter parameter is ignored and all processes are returned, the test still passes (as long as there is at least one Python process on the system, which is always true during testing). A real gate would verify that the filtered list contains ONLY processes matching the filter by checking that all process names contain "python".
- Severity: Low
- Fix recommendation: Add an assertion that all returned processes have "python" in their name: `assert all("python" in p.name.lower() for p in procs)`.

### tests/test_bridges/test_process_bridge.py:604 - test_list_processes_detailed_self_arch
- Violation(s): Weak-assertion-on-rich-output / Insufficient assertion on data correctness
- Why it is not a real gate: The test retrieves the current process's architecture and asserts it is in `{"x86_64", "x86"}`. However, it does not verify the returned architecture is CORRECT for the current process — it only checks it is one of the expected values. On a 64-bit system, both x86_64 and x86 are technically valid answers depending on whether the Python interpreter is 32-bit or 64-bit, but the test does not validate which one is actually running. A more rigorous test would compare the bridge's reported architecture to the actual running architecture (via `struct.calcsize("P")`).
- Severity: Low
- Fix recommendation: Compare the bridge's reported architecture to the canonical architecture of the running interpreter via `struct.calcsize("P") * 8 == 64` to determine if it should be x86_64 or x86, then assert the bridge matches.

### tests/test_bridges/test_process_bridge.py:726 - test_search_pattern_finds_bytes
- Violation(s): Weak-assertion-on-rich-output / Insufficient validation of search correctness
- Why it is not a real gate: The test searches for the first 8 bytes of known_buffer and asserts `addr in results`. However, it does not verify that the returned address is actually the start of the found pattern — it only checks that the expected address is somewhere in the results list. A bug where the bridge returns a nearby address (off by a page, for example) would not be caught. The test also does not verify that searching for a pattern that is NOT in memory returns an empty list.
- Severity: Medium
- Fix recommendation: Verify the pattern is found at exactly the right address by checking `results[0] == addr` (the first result). Add a second test that searches for a pattern known to NOT be in memory and asserts the results list is empty.

### tests/test_core/test_process_manager_audit6.py:127 - test_register_rejects_dead_pid
- Violation(s): Weak-assertion-on-rich-output / Fragile test due to OS behavior
- Why it is not a real gate: The test spawns a subprocess, waits for it to exit, and then tries to register its PID. However, the OS may reuse the PID very quickly for a new process. The test handles this by looping and regenerating the dead PID, but it uses a bare `else` clause with `pytest.fail`, which is confusing and fragile. More importantly, the test does not verify that the rejection is due to the PID not existing — it only catches a ValueError. A bug where the code rejects PIDs for any reason would still pass. The test also does not verify that the error message indicates a non-existent process.
- Severity: Low
- Fix recommendation: After catching the ValueError, verify the exception message contains language about the process not existing (e.g., "does not exist" or "not found"). Also use a more robust dead PID generation that retries with a longer wait if the OS recycled the PID.

### tests/test_credentials/test_env_loader_roundtrip_live.py:70 - test_quote_then_parse_round_trip
- Violation(s): Tautological / Re-implements logic in the test
- Why it is not a real gate: The test quotes a value and then parses it back, comparing to the original. However, the test is re-implementing the round-trip semantics — it quotes the value using the production `_quote_env_value`, then parses it using the production `_parse_env_text`. If both functions have the same bug (e.g., both double-escape backslashes), the test still passes. The test does not have an independent oracle of correct quoting/parsing behavior. However, this is partially mitigated by the fact that round-trip tests are common for serialization and have value even without an external oracle, as they at least detect internal inconsistencies. This is a borderline case but acceptable if the test covers diverse inputs (which it does via `_ROUND_TRIP_VALUES`).
- Severity: Low
- Fix recommendation: The test is defensible as-is because it covers a wide range of inputs and detects internal inconsistencies in the round-trip. To strengthen it, add a separate test that verifies the format of the quoted output against known-correct examples (e.g., empty string quotes as "", backslashes are doubled, etc.) to ensure the format itself is correct, not just that it round-trips.

### tests/test_hexcore_e2e/test_bookmarks.py:18 - test_list_bookmarks_empty_on_fresh_doc
- Violation(s): Weak-assertion-on-rich-output / Insufficient assertion on object type
- Why it is not a real gate: The test asserts `bookmarks == []`. However, it does not verify that `bookmarks` is actually the correct type (a list of tuples, not just any iterable equal to []). A bug where `list_bookmarks()` returns None instead of an empty list would fail, but a bug where it returns a generator or other iterable would not. The test is also very weak — it only checks the trivial case of a fresh document.
- Severity: Low
- Fix recommendation: Verify the type: `assert isinstance(bookmarks, list)`. Add a test that adds a bookmark and verifies `list_bookmarks()` returns a list with the correct structure (tuples with 4 fields in the expected order).

### tests/test_hexcore_e2e/test_bookmarks.py:37 - test_add_bookmark_returns_index
- Violation(s): Weak-assertion-on-rich-output / Insufficient assertion on return value semantics
- Why it is not a real gate: The test asserts `isinstance(idx, int) and idx >= 0`. However, it does not verify that the returned index can actually be used to identify the bookmark later (e.g., by removing it or accessing it from the list). A bug where all bookmarks return index 0 would not be caught. The test also does not verify that different bookmarks return different indices.
- Severity: Low
- Fix recommendation: Add a second test that adds multiple bookmarks, verifies they have different indices, and verifies each index can be used to remove the corresponding bookmark.

### tests/test_ui/log_viewer/test_realcov_15_tail_reader_real_logs.py:52 - test_reader_parses_real_structlog_records
- Violation(s): Weak-assertion-on-rich-output / Insufficient assertion on field structure
- Why it is not a real gate: The test emits real structlog events, starts a LogFileTailReader, and asserts that the events are parsed and contain required fields. However, it only asserts the presence of fields, not their correctness. For example, it asserts `field in alpha` for each field in `_REQUIRED_FIELDS`, but does not verify that the parsed values are correct (e.g., that the timestamp is a valid ISO format, that the level is actually "INFO" and not "ALERT", etc.). A bug where the parser returns empty strings for all fields would not be caught.
- Severity: Medium
- Fix recommendation: Extend assertions to verify field correctness: assert the timestamp parses as a valid ISO 8601 datetime, assert the level enum is a known log level, assert the logger name contains the expected module name, assert the event matches the emitted event name exactly, and assert the extras dict contains the exact key-value pairs emitted.

## Clean tests

### tests/test_audit4/b2_process_tab/conftest.py
- (Fixture only; no test functions)

### tests/test_audit4/b2_process_tab/test_process_tab.py:167 - TestF0013InjectRequiresAttachment
- All tests in this class (test_inject_warns_when_no_process_attached, test_inject_does_not_warn_when_attached) are listed under Findings above. No clean tests in this class beyond those findings.

### tests/test_audit4/b2_process_tab/test_process_tab.py:367 - test_attach_success_sets_attached_pid
- Clean: Test verifies that when the bridge's success callback is invoked, `_attached_pid` is set to the target PID. The test patches the async call to synchronously invoke the success callback with None, and then directly asserts the state change. This is a real gate because (1) it drives a real input (attachment flow) to a verified output (state update), (2) the expected value (the target PID) is independently known, and (3) breaking this in production would cause the test to fail.

### tests/test_audit4/b2_process_tab/test_process_tab.py:405 - test_suspend_error_callback_shows_warning
- Clean: Test verifies that calling `_on_suspend()` with a failure result shows a warning dialog. The test patches the async call to invoke the error callback and then asserts a warning was shown. This is a real gate because it verifies error handling in a critical path and proves the code surfaces failures.

### tests/test_audit4/b2_process_tab/test_process_tab.py:438 - test_resume_error_callback_shows_warning
- Clean: Test verifies that calling `_on_resume()` with a failure result shows a warning dialog. Same rationale as test_suspend_error_callback_shows_warning.

### tests/test_audit4/b2_process_tab/test_process_tab.py:480 - test_terminate_success_triggers_tracked_refresh
- Clean: Test verifies that after termination succeeds, both `_on_refresh` and `_refresh_tracked` are called. The test uses a subclass counter to track calls and asserts both counters increment. This is a real gate because (1) it drives a real input (termination) and verifies two specific side effects, (2) breaking either refresh in production would cause the test to fail.

### tests/test_audit4/b2_process_tab/test_process_tab.py:534 - test_terminate_attached_pid_clears_attached_state
- Clean: Test verifies that terminating an attached PID clears the `_attached_pid` state. The test patches the async call and directly asserts the state change. This is a real gate.

### tests/test_audit4/b2_process_tab/test_process_tab.py:575 - test_terminate_unattached_pid_does_not_clear_attachment
- Clean: Test verifies that terminating a different PID does not affect the current attachment. This is a real gate because it proves the code is checking PID equality before clearing.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:89 - test_region_filter_filters_table
- Clean: Test directly calls `_on_region_filter_changed("ntdll")` and verifies row visibility changes. This is a real gate because (1) it exercises the filter logic end-to-end, (2) it verifies the exact output (row 0 shown, rows 1-2 hidden), (3) breaking the filter would cause the test to fail.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:139 - test_region_filter_case_insensitive
- Clean: Test verifies the filter is case-insensitive by filtering for lowercase "kernel32" and asserting the uppercase "KERNEL32.DLL" row is shown. Real gate.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:156 - test_region_filter_empty_shows_all
- Clean: Test verifies that an empty filter reveals all rows. This is a real gate with a clear precondition (rows initially hidden) and postcondition (all rows revealed).

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:178 - test_buttons_disabled_on_init
- Clean: Test verifies that all action buttons are disabled on initialization. Real gate; breaking this would cause the test to fail.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:188 - test_buttons_enabled_after_set_attached_pid
- Clean: Test verifies that calling `set_attached_pid(1234)` enables all action buttons. Real gate.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:198 - test_buttons_disabled_after_detach
- Clean: Test verifies that calling `set_attached_pid(None)` disables all action buttons. Real gate.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:275 - test_search_status_resets_on_failure
- Clean: Test verifies that when the bridge search fails, the search status label is updated to something other than "Searching...". The test captures the error callback, calls it with a RuntimeError, and asserts the label changed. Real gate.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:316 - test_free_removes_allocation_row
- Clean: Test verifies that after a successful free operation, the matching Allocated row is removed from the table. The test manually populates the table, calls the success callback, and counts rows. Real gate.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:367 - test_free_does_not_add_freed_row
- Clean: Test verifies that the free success callback never adds a new row. Real gate.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:410 - test_invalid_protect_address_shows_messagebox
- Clean: Test verifies that an invalid address to `_on_protect()` shows a critical messagebox. Real gate.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:437 - test_invalid_free_address_shows_messagebox
- Clean: Test verifies that an invalid address to `_on_free()` shows a critical messagebox. Real gate.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:464 - test_invalid_protect_address_message_contains_input
- Clean: Test verifies that the error message includes the bad input text. Real gate.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:495 - test_prot_addr_has_placeholder
- Clean: Test verifies that the protect address field has a placeholder containing "0x" or "7FF". Real gate.

### tests/test_audit4/b4_memory_tab/test_memory_tab.py:507 - test_prot_addr_placeholder_matches_expected_format
- Clean: Test verifies the placeholder contains a realistic 64-bit address format. Real gate.

### tests/test_audit4/b4_memory_tab/test_realcov_14a_memory_tab.py:157 - test_format_memory_renders_real_pe_header
- Clean: Test reads real bytes from ntdll's image base (guaranteed to start with MZ due to PE format) and verifies the formatter renders the MZ signature in hex and ASCII. This is a real gate with real data (the actual PE header of ntdll) and a verified-correct expected value (the MZ signature).

### tests/test_audit4/b4_memory_tab/test_realcov_14a_memory_tab.py:180 - test_format_memory_hex_matches_real_bytes
- Clean: Test reads real bytes from ntdll and verifies the hex formatter output contains the bytes in correct hex form. Real gate with real data.

### tests/test_audit4/b4_memory_tab/test_realcov_14a_memory_tab.py:195 - test_region_map_populated_from_real_memory_map
- Partially clean (but see Findings). The core assertion is real (the table is populated), but the validation is weak. Listed under Findings.

### tests/test_audit4/b4_memory_tab/test_realcov_14a_memory_tab.py:222 - test_region_map_contains_real_module_region
- Partially clean (but see Findings). The test verifies ntdll's base falls within a region, but does not validate the region's correctness. Listed under Findings.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:395 - test_commit_int32_fires_notify_data_modified
- Clean: Test verifies that toggling a bit calls `_on_bit_toggled()` and fires a DATA_MODIFIED event with the correct offset (5), length (1), and source containing "data_inspector". This is a real gate with verified-correct expected values (offset=5 from the fixture, length=1 for a byte).

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:418 - test_no_notify_when_document_is_none
- Clean: Test verifies that when document is None, no DATA_MODIFIED is published. Real gate.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:434 - test_no_notify_when_set_bit_raises
- Clean: Test verifies that when `set_bit` raises, no notification is published. Real gate.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:451 - test_notify_uses_correct_source_namespace
- Clean: Test verifies the source starts with "hex-editor.data_inspector". Real gate.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:483 - test_encode_text_no_doc_surfaces_error
- Clean: Test verifies that when document is None, the output label contains "No document open". Real gate.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:503 - test_no_fallback_bytes_generated
- Clean: Test verifies that with no document, the output does NOT contain the hex-encoded result. Real gate.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:531 - test_no_doc_no_bridge_call
- Clean: Test verifies the bridge is not invoked when no document is open. Real gate.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:563 - test_encode_text_with_doc_routes_through_bridge
- Clean: Test verifies the bridge `encode_text` is called with the input text and encoding. Real gate.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:588 - test_encode_text_output_uses_bridge_result
- Clean: Test verifies the output label displays the hex string returned by the bridge (formatted with spaces). Real gate with verified expected output.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:611 - test_encode_text_no_bridge_surfaces_error
- Clean: Test verifies that when doc is open but bridge is None, an error is surfaced. Real gate.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:646 - test_update_bit_buttons_continues_past_error
- Clean: Test verifies that when bit 3's `get_bit` raises, that button shows "?", is disabled, and all other buttons are still updated. This is a real gate with concrete inputs (8 bit buttons, error on one) and verified outputs (specific labels and enabled states for each button).

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:677 - test_all_bits_updated_when_no_errors
- Clean: Test verifies all 8 buttons are updated when no errors occur, with correct text ("0" or "1") and enabled state. Real gate.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:698 - test_multiple_error_bits_all_marked
- Clean: Test verifies that multiple error bits (0, 4, 7) are each marked with "?" and disabled independently. Real gate.

### tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py:723 - test_early_error_does_not_prevent_later_bits_being_updated
- Clean: Test verifies that error on bit 7 (first iterated) does not block bits 6-0 from being updated. This directly tests the regression fix. Real gate.

### tests/test_audit5/u7_ui_providerconfig/test_provider_specific_ui.py:108 - test_resources_group_present_for_previously_unwired_providers
- Clean: Test parametrizes over previously unwired providers and verifies each has a Resources group with expected buttons. Real gate.

### tests/test_audit5/u7_ui_providerconfig/test_provider_specific_ui.py:137 - test_resource_links_table_covers_all_cloud_providers
- Clean: Test verifies the static resource links table includes entries for all cloud providers with non-empty values and HTTPS URLs. Real gate.

### tests/test_audit5/u7_ui_providerconfig/test_provider_specific_ui.py:191 - test_previously_wired_providers_retain_their_groups
- Clean: Test verifies that providers like "ollama" retain their original group (e.g., "Model Download"). Real gate.

### tests/test_audit5/u7_ui_providerconfig/test_provider_specific_ui.py:215 - test_openrouter_gets_both_cost_and_resources_groups
- Clean: Test verifies OpenRouter has both "Cost Tracking" and "Resources" groups. Real gate.

### tests/test_audit5/u7_ui_providerconfig/test_provider_specific_ui.py:230 - test_open_resource_url_warns_when_qdesktopservices_fails
- Clean: Test verifies that when `QDesktopServices.openUrl` returns False, a warning is shown. Real gate.

### tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py:131 - test_available_types_are_a_subset_of_real_probes
- Partially clean (but see Findings). The core assertion is that reported types match independent real probes, but the test does not verify the manager is actually making the real calls. Listed under Findings.

### tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py:161 - test_probe_result_is_cached_after_real_probe
- Clean: Test verifies that a real probe result is cached verbatim. The test calls `probe_and_cache()` which probes the host and returns both the probe result and the cached value, and asserts they are equal. Real gate.

### tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py:175 - test_get_returns_the_real_managed_instance
- Clean: Test registers a real QEMUSandbox instance and verifies `get()` returns the exact same object. Real gate.

### tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py:190 - test_active_count_counts_real_running_instances
- Clean: Test registers one running and one stopped sandbox instance, verifies `active_count` is 1. Real gate.

### tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py:201 - test_destroy_routes_through_real_qemu_stop
- Clean: Test registers a real instance and calls `destroy()`, verifies the instance is removed and the sandbox state transitions to "stopped". Real gate with real data (real QEMUSandbox).

### tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py:215 - test_destroy_all_stops_every_real_instance
- Clean: Test registers two real instances and calls `destroy_all()`, verifies both are removed and both transition to "stopped". Real gate.

### tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py:232 - test_cleanup_stale_removes_real_idle_instance
- Clean: Test registers two instances with different idle times, calls `cleanup_stale()` with a 3600-second threshold, verifies the old one is cleaned and the new one remains. Real gate with real data.

### tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py:252 - test_get_status_reports_real_instances_and_real_availability
- Clean: Test registers a real instance and calls `get_status()`, verifies the response contains the instance id, type, and available types from real probes. Real gate.

### tests/test_audit7/sandbox_monitors/conftest.py
- (Fixture and hook; no test functions)

### tests/test_audit7/sandbox_monitors/test_dll_log_parser.py:45 - test_legacy_six_column_row_still_parses
- Clean: Test writes a legacy 6-column DLL log row and calls `parse_dll_log()`, verifies all fields parse correctly including the new fields (event_id=0, empty payload_schema). Real gate with known-good legacy format.

### tests/test_audit7/sandbox_monitors/test_dll_log_parser.py:72 - test_extended_eight_column_parsed_row
- Clean: Test writes an extended 8-column row and verifies it parses with event_id=5 and empty payload_schema. Real gate.

### tests/test_audit7/sandbox_monitors/test_dll_log_parser.py:94 - test_extended_eight_column_unparsed_row_carries_event_id_and_schema
- Clean: Test writes an unparsed row (with empty image_path) and verifies event_id and payload_schema are carried through. Real gate.

### tests/test_audit7/sandbox_monitors/test_dll_log_parser.py:125 - test_mixed_legacy_and_extended_rows
- Clean: Test writes a mix of legacy and extended rows, verifies they all parse correctly with respective fields. Real gate with diverse inputs.

### tests/test_audit7/sandbox_monitors/test_dll_log_parser.py:152 - test_malformed_short_row_is_skipped
- Clean: Test writes a short malformed row followed by a valid row, verifies the short row is skipped and the valid row is parsed. Real gate.

### tests/test_audit7/ui_panels_process/conftest.py
- (Fixture only; no test functions)

### tests/test_audit7/ui_panels_process/test_threads_auto_refresh.py:207 - test_auto_refresh_button_exists_and_is_checkable
- Clean: Test verifies the auto-refresh button exists and is checkable. Real gate.

### tests/test_audit7/ui_panels_process/test_threads_auto_refresh.py:329 - test_button_text_reflects_state
- Clean: Test verifies the button text changes between "Auto-Refresh: ON" and "Auto-Refresh: OFF" based on state. Real gate.

### tests/test_audit7/ui_panels_process/test_threads_auto_refresh.py:344 - test_cleanup_stops_timer
- Clean: Test verifies that calling `cleanup()` stops the auto-refresh timer. Real gate.

### tests/test_audit7/ui_panels_process/test_threads_auto_refresh.py:361 - test_uses_3000ms_interval
- Clean: Test verifies the timer interval is exactly 3000 ms. Real gate.

### tests/test_bridges/test_process_bridge.py:444 - TestInitialization
- All test functions in this class (test_initialize_loads_kernel32, test_initialize_loads_ntdll, etc.) pass the real gate test because they verify actual state after calling `initialize()` against real Windows APIs. Real gates.

### tests/test_bridges/test_process_bridge.py:513 - TestProcessListing
- test_list_processes_non_empty, test_list_processes_includes_self, test_list_processes_has_python_name: These are real gates that verify against real process state.

### tests/test_bridges/test_process_bridge.py:554 - test_list_processes_detailed_has_fields
- Clean: Test verifies the detailed listing includes expected keys. Real gate.

### tests/test_bridges/test_process_bridge.py:592 - test_detect_architecture_self
- Clean: Test verifies architecture detection returns the canonical architecture of the current process. Real gate with verified-correct expected value.

### tests/test_bridges/test_process_bridge.py:612 - TestProcessOpenClose
- test_open_process_query, test_close_resets_state, test_open_invalid_pid_raises: All real gates that verify state transitions and error handling against real Windows API behavior.

### tests/test_bridges/test_process_bridge.py:657 - TestMemoryOperations
- test_read_memory_known_buffer, test_write_read_roundtrip, test_allocate_free_cycle, test_protect_returns_old_protection: All real gates with real data (known buffers) and verified expected outputs.

### tests/test_bridges/test_process_bridge.py:756 - TestThreadEnumeration
- test_get_threads_non_empty, test_get_threads_have_tid, test_get_threads_start_address_nonzero, test_get_threads_state_not_unknown, test_get_threads_expose_pc_fields: All real gates with verified-correct expected values (TIDs > 0, known state strings, etc.).

### tests/test_bridges/test_process_bridge.py:806 - TestModuleListing
- test_get_modules_non_empty, test_get_modules_includes_python, test_get_modules_have_base_address: Real gates with verified-correct expected values.

### tests/test_bridges/test_process_bridge.py:847 - TestProcessInfo
- test_get_process_info_self, test_get_process_info_no_pid: Real gates.

### tests/test_bridges/test_process_bridge.py:872 - TestTokenPrivileges
- test_get_token_privileges_has_entries, test_get_token_privileges_has_sechangenotify, test_get_token_privileges_entry_keys: Real gates with verified expected structure and known-correct privilege names.

### tests/test_bridges/test_process_bridge.py:914 - TestHandleEnumeration
- test_get_handles_returns_list, test_get_handles_have_fields: Real gates.

### tests/test_bridges/test_process_bridge.py:938 - TestWindowEnumeration
- test_get_windows_no_crash: Real gate.

### tests/test_bridges/test_process_bridge.py:951 - TestServiceListing
- test_list_services_returns_list, test_list_services_have_name_state: Real gates.

### tests/test_bridges/test_process_bridge.py:975 - TestPebTebAccess
- test_read_peb_has_address, test_read_peb_has_image_base: Real gates with verified-correct expected values (addresses > 0).

### tests/test_core/test_process_manager_audit6.py:116 - test_register_rejects_zero_pid
- Clean: Test verifies PID 0 is rejected with a ValueError. Real gate.

### tests/test_core/test_process_manager_audit6.py:148 - test_register_accepts_live_pid
- Clean: Test spawns a real subprocess, registers its PID, and verifies it's in the registry. Real gate with real data.

### tests/test_core/test_process_manager_audit6.py:163 - test_register_accepts_self_pid
- Clean: Test registers the current process's PID and verifies it's in the registry. Real gate.

### tests/test_core/test_process_manager_audit6.py:181 - test_atexit_cleanup_calls_sync_cleanup_once
- Clean: Test verifies `_atexit_cleanup` calls `_sync_cleanup` exactly once. Real gate with direct counting.

### tests/test_core/test_process_manager_audit6.py:222 - test_install_handlers_registers_atexit_only_once
- Clean: Test verifies repeated `install_handlers` calls do not stack atexit hooks. Real gate.

### tests/test_core/test_process_manager_audit6.py:249 - test_signal_handler_returns_quickly_without_loop
- Clean: Test verifies the signal handler returns quickly (< 1s) even when cleanup is slow. Real gate with timing verification.

### tests/test_core/test_process_manager_audit6.py:289 - test_signal_handler_uses_running_loop_when_available
- Clean: Test verifies the handler schedules async cleanup when a loop is running. Real gate.

### tests/test_credentials/test_env_loader_roundtrip_live.py:70 - test_quote_then_parse_round_trip
- Partially clean (but see Findings). Round-trip test with diverse inputs; acceptable despite tautological nature because it detects internal inconsistencies.

### tests/test_credentials/test_env_loader_roundtrip_live.py:85 - test_save_to_env_file_round_trip
- Clean: Test saves a value to an .env file and reloads it, verifying round-trip correctness. Real gate with real file I/O.

### tests/test_credentials/test_env_loader_roundtrip_live.py:104 - test_save_to_env_file_update_preserves_other_lines
- Clean: Test verifies that updating a key in .env preserves comments and sibling variables. Real gate with real file parsing and rewriting.

### tests/test_credentials/test_env_loader_roundtrip_live.py:128 - test_save_to_env_file_preserves_crlf_line_endings
- Clean: Test verifies CRLF line endings are preserved by the writer. Real gate with real file I/O and binary verification.

### tests/test_credentials/test_env_loader_roundtrip_live.py:150 - test_save_to_env_file_new_file_uses_lf
- Clean: Test verifies a new .env file uses LF line endings. Real gate.

### tests/test_credentials/test_env_loader_roundtrip_live.py:168 - test_parse_mixed_quoted_and_unquoted
- Clean: Test parses a real mixed .env file and verifies all values parse correctly. Real gate with known-good inputs.

### tests/test_credentials/test_env_loader_roundtrip_live.py:200 - test_parser_accepts_crlf_file
- Clean: Test verifies the parser handles CRLF transparently. Real gate.

### tests/test_credentials/test_env_loader_roundtrip_live.py:214 - test_quote_env_value_unquoted_safe_chars
- Clean: Test verifies safe characters are emitted without quotes. Real gate.

### tests/test_credentials/test_env_loader_roundtrip_live.py:220 - test_quote_env_value_quotes_when_needed
- Clean: Test verifies the quoter wraps unsafe values and escapes correctly. Real gate with verified-correct expected escapes.

### tests/test_credentials/test_env_loader_roundtrip_live.py:231 - test_quote_env_value_empty
- Clean: Test verifies empty values serialize correctly and parse back. Real gate.

### tests/test_hexcore_e2e/test_bookmarks.py:27 - test_add_bookmark_returns_index
- Partially clean (but see Findings). Test verifies the return type but not usability.

### tests/test_hexcore_e2e/test_bookmarks.py:37 - test_list_bookmarks_contains_added_bookmark
- Clean: Test adds a bookmark and verifies it appears in the list. Real gate.

### tests/test_hexcore_e2e/test_bookmarks.py:47 - test_bookmark_fields_match
- Clean: Test verifies a bookmark's fields match what was added. Real gate with verified-correct field values.

### tests/test_hexcore_e2e/test_bookmarks.py:66 - test_add_multiple_bookmarks_preserves_order
- Clean: Test adds multiple bookmarks and verifies they are returned in insertion order. Real gate.

### tests/test_hexcore_e2e/test_bookmarks.py:88 - test_remove_bookmark_by_index
- Clean: Test removes a bookmark by index and verifies it no longer appears. Real gate.

### tests/test_hexcore_e2e/test_bookmarks.py:101 - test_remove_bookmark_returns_false_for_invalid_index
- Clean: Test verifies removal of an out-of-range index returns False. Real gate.

### tests/test_hexcore_e2e/test_bookmarks.py:110 - test_bookmark_survives_write_operation
- Clean: Test adds a bookmark, writes to the document, and verifies the bookmark still exists. Real gate.

### tests/test_hexcore_e2e/test_bookmarks.py:122 - test_remove_one_of_multiple_bookmarks_leaves_others
- Clean: Test removes one bookmark from a set and verifies the others remain. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:23 - test_empty_doc_has_zero_length
- Clean: Test verifies a fresh HexDocument has length 0. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:31 - test_open_bytes_creates_doc_with_correct_length
- Clean: Test verifies `open_bytes()` creates a document with correct length. Real gate with verified-correct expected value.

### tests/test_hexcore_e2e/test_document_lifecycle.py:41 - test_open_bytes_content_matches_input
- Clean: Test verifies the bytes stored in the document match the input exactly. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:51 - test_open_from_file_has_correct_length
- Clean: Test verifies a file-opened document has correct length. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:60 - test_open_from_file_content_matches_file
- Clean: Test verifies file content is preserved exactly. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:69 - test_in_memory_doc_file_path_is_none
- Clean: Test verifies an in-memory document returns None for file_path(). Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:77 - test_file_opened_doc_returns_path
- Clean: Test verifies a file-opened document returns the correct path. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:92 - test_empty_doc_file_path_is_none
- Clean: Test verifies a fresh document has no file path. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:100 - test_open_nonexistent_file_raises
- Clean: Test verifies opening a non-existent file raises an exception. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:111 - test_open_empty_file_succeeds_with_zero_length
- Clean: Test verifies opening a zero-byte file works. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:127 - test_save_writes_correct_content_to_disk
- Clean: Test saves a document and verifies the disk content matches exactly. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:142 - test_save_as_creates_new_file
- Clean: Test verifies `save_as()` creates a new file with correct content. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:156 - test_is_modified_false_after_save
- Clean: Test verifies `is_modified()` returns False after saving. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:173 - test_save_then_reopen_preserves_data
- Clean: Test saves modifications and reopens, verifying data survives round-trip. Real gate.

### tests/test_hexcore_e2e/test_document_lifecycle.py:193 - test_save_as_original_unchanged
- Clean: Test verifies `save_as` does not overwrite the original file. Real gate.

### tests/test_ui/log_viewer/test_realcov_15_tail_reader_real_logs.py:52 - test_reader_parses_real_structlog_records
- Partially clean (but see Findings). Test exercises real logging but with weak field assertions.

### tests/test_ui/log_viewer/test_realcov_15_tail_reader_real_logs.py:97 - test_reader_picks_up_live_real_appends
- Clean: Test emits real events after starting the reader and verifies live appends are detected. Real gate with real logging I/O.

## Summary

- **Findings by severity:**
  - Critical: 0
  - High: 5
  - Medium: 14
  - Low: 11

- **Total tests audited:** 308

- **Total tests clean:** 273

- **Total tests with findings:** 35
