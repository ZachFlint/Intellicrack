# F23 — Win32 / ctypes call pre-call logs

## Fix description

Per §2.3, Win32 / ctypes calls (DLL loads, API entry-point assignments, EnumWindows, OpenProcess, etc.) must be logged on both intent and outcome. Many sites log only the failure or only the success.

## Sites to fix

### `src/intellicrack/bridges/_win32_types.py`

DLL load helpers — each currently silent on the success path and unwrapped (any ImportError/OSError from ctypes propagates uncaught):

| Line | Helper | Fix |
|-----:|--------|-----|
| 890 | `get_kernel32()` `ctypes.windll.kernel32` | `_logger.debug("win32_dll_loaded", name="kernel32")` after cache miss |
| 902 | `get_ntdll()` | Same with `name="ntdll"` |
| 914 | `get_advapi32()` | Same with `name="advapi32"` |
| 926 | `get_user32()` | Same with `name="user32"` |
| 938 | `get_dbghelp()` | Same with `name="dbghelp"` |
| 950 | `get_psapi()` | Same with `name="psapi"` |

(All LOW severity — passive handle caches behind thin accessors. Optionally wrap each in try/except too.)

### `src/intellicrack/ui/win32_embed.py`

| Lines | Function | Fix |
|-------|----------|-----|
| 100-113 | `_get_user32()` `ctypes.WinDLL("user32", use_last_error=True)` | `_logger.debug("win32_user32_loaded")` after L112 |
| 62-97 | `_configure_user32(user32)` assigns argtypes/restype | `_logger.debug("win32_user32_configured")` at function end |
| 116-173 | `find_window_by_pid` — `EnumWindows`, `GetWindowThreadProcessId`, `IsWindowVisible`, `GetWindow`, `GetWindowTextW` | `_logger.debug("win32_window_search_started", pid=pid)` at L128; `_logger.debug("win32_window_not_found", pid=pid)` before final `return None` |
| 176-222 | `_reparent_foreign_hwnd` — `GetWindowLongPtrW`, `SetWindowLongPtrW`, `SetParent` | `_logger.debug("win32_hwnd_reparented", hwnd=hex(hwnd), parent=hex(parent_hwnd))` before `return True` |

### `src/intellicrack/ui/panels/hex_editor/_process_memory.py`

| Lines | Function | Fix |
|-------|----------|-----|
| 162-202 | `_list_regions_ctypes()` — `ctypes.windll.kernel32.OpenProcess` (L167), `VirtualQueryEx` (L180), `CloseHandle` (L197) | Add pre-call debug logs for each Win32 API site naming PID + access mask, plus success exit log with region count |
| 131-154 | `_on_list_regions()` dispatch | Entry log `process_regions_query_started` with PID |
| 204-241 | `_list_regions_procfs()` reads `/proc/{pid}/maps` | Pre-read debug log |

### `src/intellicrack/providers/gpu_pci_resources.py`

| Lines | Function | Fix |
|-------|----------|-----|
| 93-106 | `_Cfgmgr32.__init__` `ctypes.WinDLL("cfgmgr32.dll")` + function-pointer resolution | `_logger.debug("cfgmgr32_loaded")` after successful DLL load |
| 228-260 | `enumerate_pci_memory_bars(device_id)` walks PnP resources | Add entry/exit debug logs |

### `src/intellicrack/providers/xpu_utils.py`

| Lines | Function | Fix |
|-------|----------|-----|
| 156-198 | `_get_windows_gpu_info()` `ProcessManager.get_instance().run_tracked(...)` PowerShell WMI/registry queries | `_logger.debug("windows_gpu_info_starting")` before run_tracked |

## Acceptance criteria

- [ ] All Win32 DLL loads have post-load debug logs
- [ ] All EnumWindows / OpenProcess / VirtualQueryEx / SetParent / SetWindowLongPtrW call sites have surrounding logs
- [ ] cfgmgr32 + PnP enumeration logged
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
