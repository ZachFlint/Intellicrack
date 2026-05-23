# F28 — Sandbox public operation entry logs

## Fix description

Both `sandbox/qemu.py` and `sandbox/windows.py` consistently skip entry-time logging on their public action methods. State mutations, success summaries, and error paths are all well-logged, but the "operation started" signal is missing. Adding a `_logger.info("<op>_started", ...)` at the top of each public method enables operators to follow the sequence at default INFO log level without enabling debug.

## Sites to fix

### `src/intellicrack/sandbox/qemu.py`

| Lines | Method | Suggested entry log |
|-------|--------|---------------------|
| 2478 | `run_command()` | `_logger.info("qemu_run_command_started", instance_id=..., command=..., timeout=...)` |
| 2719 | `run_binary()` | `_logger.info("qemu_run_binary_started", instance_id=..., binary=..., args=...)` |
| 2935 | `copy_to_sandbox()` | `_logger.info("qemu_copy_to_started", instance_id=..., source=..., dest=...)` |
| 2962 | `copy_from_sandbox()` | `_logger.info("qemu_copy_from_started", instance_id=..., source=..., dest=...)` |
| 2990 | `take_snapshot()` | `_logger.info("qemu_snapshot_started", instance_id=..., name=...)` |
| 3013 | `restore_snapshot()` | `_logger.info("qemu_restore_started", instance_id=..., snapshot_id=...)` |
| 3054 | `delete_snapshot()` | `_logger.info("qemu_snapshot_delete_started", instance_id=..., name=...)` |
| 3177 | `capture_screenshot()` | `_logger.info("qemu_screenshot_started", instance_id=...)` |
| 3236 | `apply_anti_evasion()` | `_logger.info("qemu_anti_evasion_started", instance_id=..., techniques=...)` |
| 3326 | `dump_memory()` | `_logger.info("qemu_memory_dump_started", instance_id=...)` |
| 3382 | `extract_dropped_files()` | `_logger.info("qemu_extract_dropped_files_started", instance_id=...)` |
| 3584 | `yara_scan()` | `_logger.info("qemu_yara_scan_started", instance_id=..., rule_source=...)` |

### `src/intellicrack/sandbox/windows.py`

| Lines | Method | Suggested entry log |
|-------|--------|---------------------|
| 1306 | `run_command()` | `_logger.info("windows_run_command_started", instance_id=..., command=...)` |
| 1374 | `run_binary()` | `_logger.info("windows_run_binary_started", instance_id=..., binary=..., args=...)` |
| 1411 | (inside `run_binary`) `copy_to_sandbox(binary_path, ...)` | Promote `copy_to_sandbox` log from debug to info inside `run_binary` |
| 1526 | `copy_to_sandbox()` | `_logger.info("windows_copy_to_started", ...)` |
| 1557 | `copy_from_sandbox()` | `_logger.info("windows_copy_from_started", ...)` |
| 1674 | `capture_screenshot()` | `_logger.info("windows_screenshot_started", ...)` |
| 1726 | `apply_anti_evasion()` | `_logger.info("windows_anti_evasion_started", ...)` |
| 1924 | `dump_memory()` | `_logger.info("windows_memory_dump_started", ...)` |
| 2089 | `extract_dropped_files()` | `_logger.info("windows_extract_dropped_files_started", ...)` |
| 2176 | `yara_scan()` | `_logger.info("windows_yara_scan_started", ...)` |

## Acceptance criteria

- [ ] All 22 sandbox public methods emit an info-level `<op>_started` log at entry
- [ ] Existing success/failure logs preserved
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
