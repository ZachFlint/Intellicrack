# Production Defects Surfaced by Test-Gate Remediation

Defects found while writing correct falsifiable gates. Per remediation rule 1, the production source was NOT modified; the correct gate was written and stays RED until the source is fixed.

## PD-001: resource_exists
- **Source:** `src/intellicrack/ui/resources/resource_helper.py`:186
- **Test file:** `tests/test_ui/test_resource_helper.py`
- **Expected:** resource_exists("") returns False — an empty path is not an existing resource
- **Actual:** resource_exists("") returns True because get_resource_path("") normalizes the empty string to "" and `assets_dir / ""` evaluates to the assets directory itself (which exists), so path.exists() is True
- **Red gate:** `tests/test_ui/test_resource_helper.py::TestResourceExists::test_returns_false_for_empty_path`
- **Sandbox status:** pending (expected red)

## PD-002: ProcessBridge.time_thread_wait
- **Source:** `src/intellicrack/bridges/process.py`:6641
- **Test file:** `tests/test_bridges/test_process_win32.py`
- **Expected:** OpenThread called with THREAD_QUERY_INFORMATION | SYNCHRONIZE (0x00100040) so WaitForSingleObject has the required SYNCHRONIZE access right and can return WAIT_OBJECT_0 or WAIT_TIMEOUT
- **Actual:** OpenThread called with only THREAD_QUERY_INFORMATION (0x0040), which lacks SYNCHRONIZE; WaitForSingleObject always returns WAIT_FAILED, and the WAIT_FAILED branch in _time_wait_on_handle is unreachable because ctypes returns signed -1 while WAIT_FAILED constant is 0xFFFFFFFF, so result is 'other_-1'
- **Red gate:** `test_time_thread_wait_exited_thread_signals`
- **Sandbox status:** pending (expected red)

## PD-003: ProcessBridge._time_wait_on_handle
- **Source:** `src/intellicrack/bridges/process.py`:6676
- **Test file:** `tests/test_bridges/test_process_win32.py`
- **Expected:** WAIT_FAILED comparison accounts for ctypes returning a signed integer; the branch 'wait_result == WAIT_FAILED' matches when WaitForSingleObject returns -1 (signed) / 0xFFFFFFFF (unsigned)
- **Actual:** Comparison 'wait_result == WAIT_FAILED' is -1 == 4294967295 which is False; the else branch executes and returns 'other_-1' instead of 'failed'
- **Red gate:** `test_time_thread_wait_running_thread_times_out`
- **Sandbox status:** pending (expected red)

## PD-004: _get_pattern_registry
- **Source:** `src/intellicrack/bridges/hex_editor.py`:1774
- **Test file:** `tests/test_hexcore_e2e/test_bridge_pattern_engine.py`
- **Expected:** project_root = Path(__file__).resolve().parents[3]  # project root (C:\app)
- **Actual:** project_root = Path(__file__).resolve().parents[2]  # resolves to C:\app\src, one level too shallow
- **Red gate:** `test_list_hexpat_patterns_items_have_required_keys`
- **Sandbox status:** pending (expected red)
