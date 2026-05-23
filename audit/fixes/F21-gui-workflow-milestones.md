# F21 — GUI workflow milestone logs (§2.4)

## Fix description

Per §2.4, "GUI workflow milestones (target loaded, analysis queued, etc.)" must be logged. `ui/app.py` (the MainWindow) currently emits only UI status-bar text for most milestones. This is the central orchestration layer; logs here unify the audit trail across the rest of the app.

## Sites to fix in `src/intellicrack/ui/app.py`

### Binary lifecycle

| Lines | Method | Suggested log |
|-------|--------|---------------|
| 1366-1375 | `_on_load_binary` (file dialog → load) | `_logger.info("load_binary_dialog_opened")` on entry; log selection/cancel branch |
| 1377-1404 | `_load_binary(path)` central "binary loaded" milestone | `_logger.info("binary_loaded", path=str(path), name=path.name)` |
| 2784-2786 | `_on_open_binary` forwards to `_load_binary` | (Closed by above) |
| 2833-2840 | `_on_debug_current_binary` routes to x64dbg | `_logger.info("debug_binary_requested", binary=str(self.current_binary))` |
| 2841-2847 | `_on_analyze_current_binary` routes to Cutter | `_logger.info("analyze_binary_requested", binary=...)` |
| 2849-2855 | `_on_hex_edit_current_binary` routes to hex editor | `_logger.info("hex_edit_binary_requested", binary=...)` |
| 2857-2863 | `_on_open_binary_in_ghidra` routes to Ghidra | `_logger.info("ghidra_open_binary_requested", binary=...)` |

### Session lifecycle

| Lines | Method | Suggested log |
|-------|--------|---------------|
| 1406-1448 | `_on_new_session` | `_logger.info("session_create_requested", provider=..., model=..., name=...)` |
| 1450-1463 | `_on_load_session` | `_logger.info("session_load_dialog_opened")` |
| 1465-1478 | `_on_session_load_requested(session_id)` | `_logger.info("session_load_requested", session_id=session_id)` |
| 1501-1508 | `_on_save_session` | `_logger.info("session_save_requested")` |

### Export operations (file writes, §2.3)

| Lines | Method | Suggested log |
|-------|--------|---------------|
| 1510-1529 | `_on_export_chat` writes via `Path(path).open("w")` | `_logger.info("chat_export_started", path=path, message_count=len(messages))` before; `chat_export_completed` after |
| 1531-1579 | `_on_export_session` worker dispatch | `_logger.info("session_export_started", session_id=session.id, path=path)` |
| 1581-1610 | `_on_import_session` worker dispatch | `_logger.info("session_import_started", path=...)` |
| 1709-1741 | `_on_export_analysis` writes JSON via `Path(path).open("w")` | `_logger.info("analysis_export_started/_completed", path=path)` |
| 1686-1707 | `_on_save_patched_binary` triggers hex editor save | Log entry, decision branch, completion |

### Other workflow milestones

| Lines | Method | Suggested log |
|-------|--------|---------------|
| 2017-2072 | `_on_refresh_models` reads providers.json + refreshes | `_logger.info("models_refresh_requested", provider=provider_id, has_credentials=bool(api_key))` |
| 2091-2107 | `_on_browse_models` schedules `active_provider.list_models()` | `_logger.info("provider_list_models_requested", provider=...)` |
| 2244-2258 | `_on_configure_sandbox` | `_logger.info("sandbox_config_dialog_opened")` |
| 2431-2473 | `_on_open_sandbox` probe + creation | `_logger.info("sandbox_open_requested")` + explicit unavailable branch |
| 2475-2491 | `_on_preferences` | `_logger.info("preferences_dialog_opened")` |
| 2533-2538 | `_on_xpu_status` | `_logger.debug("xpu_status_dialog_opened")` |
| 2540-2561 | `_on_about` | Optional `_logger.debug("about_dialog_opened", code_font=..., ui_font=...)` |
| 2788-2806 | `_on_open_sandbox_panel` bridge wiring | `_logger.info("sandbox_panel_opened", bridge_attached=bool(bridge))` |
| 3016-3077 | `closeEvent` shutdown path | `_logger.info("main_window_closing")` near start, `_logger.info("main_window_closed")` near end |

### Lower-priority debug context

| Lines | Method | Suggested log |
|-------|--------|---------------|
| 295-313 | `_apply_smart_window_size` early returns | `_logger.debug("screen_geometry_unavailable_using_default")` |
| 1147-1167 | `_on_bridge_analysis_received` | Debug log |
| 1195-1212 | `_on_user_message` | `_logger.debug("user_message_received", length=len(text))` |
| 1233-1266 | `_on_tool_result` | `_logger.debug("tool_result_received", tool_name=..., success=..., duration_ms=...)` |
| 2980-2986 | `_on_sandbox_toggled` | Debug log |
| 2988-3005 | `_on_auto_approve_toggled` | Debug log |

## Sites to fix in `src/intellicrack/ui/tools.py`

| Lines | Method | Suggested log |
|-------|--------|---------------|
| 1513-1534 | `open_in_ghidra(file_path)` | `_logger.info("open_in_ghidra_requested", binary_path=str(path))` on entry + completion log |
| 1536-1556 | `open_in_hex_editor(file_path)` | Same pattern |
| 1558-1585 | `open_in_x64dbg(file_path, is_64bit)` | Same with `is_64bit` |
| 1587-1610 | `open_in_cutter(file_path)` | Already has entry log L1606; add exit |
| 2042-2049 | `log_frida_message(message)` | `_logger.debug("frida_console_message", length=len(message))` |
| 2051-2064 | `add_frida_hook_entry(hook_info)` | `_logger.info("frida_hook_registered", address=..., function=..., hook_id=...)` |
| 2240-2252 | `wire_sandbox_bridge(bridge)` | `_logger.info("sandbox_bridge_wired", deferred=self.sandbox_panel is None)` |
| 2300-2318 | `wire_script_backend(backend, validator)` | `_logger.info("script_backend_wired", deferred=..., has_validator=...)` |
| 2388-2397 | `save_hex_editor` | `_logger.info("hex_editor_save_invoked/_result", success=...)` |

## Acceptance criteria

- [ ] All listed workflow milestones emit an info-level structured log
- [ ] User-driven business events (load, save, session, export, dialog open) use `info` not `debug`
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
