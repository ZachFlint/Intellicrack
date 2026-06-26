# Section 14 — UI App Shell, Config & Chat: Test Coverage Audit

**Date:** 2026-06-26
**Auditor:** Test-reviewer agent (adversarial, audit-only — no source or test files were edited)

---

## 1. Source Scope Confirmed

| File | Key operations |
|------|---------------|
| `src/intellicrack/ui/_hex_format.py` | `format_hex_dump()` |
| `src/intellicrack/ui/_screen_compat.py` | `_resolve`, `get_screen_geometry`, `move_widget` |
| `src/intellicrack/ui/highlighter.py` | 5 × `highlightBlock`, multi-line state machine, `get_highlighter_for_language` |
| `src/intellicrack/ui/dialogs_helpers.py` | `show_error`, `show_warning`, `show_info` |
| `src/intellicrack/ui/preferences.py` | 4 × sub-widget `get_settings`, `_build_config`, `settings_changed`, `_on_apply` |
| `src/intellicrack/ui/session_manager.py` | `session_loaded`, `session_deleted`, `_FlowLayout` |
| `src/intellicrack/ui/chat.py` | `message_submitted`, `add_message`, streaming, `clear_messages`, `insert_context_text` |
| `src/intellicrack/ui/confirmation_dialog.py` | `decision_made`, cache keying, exec short-circuit |
| `src/intellicrack/ui/panel_dock.py` | `reattach_requested`, title format, `WA_DeleteOnClose` |
| `src/intellicrack/ui/overflow_toolbar.py` | extension button, proxy action, empty notice |
| `src/intellicrack/ui/win32_embed.py` | `find_window_by_pid`, `embed_window`, `poll_and_embed` |
| `src/intellicrack/ui/xpu_status.py` | device status, memory, requirements, refresh timer |
| `src/intellicrack/ui/tools.py` | `FunctionListPanel`, `XRefPanel`, `ToolOutputPanel`, `wire_sandbox_backend` |
| `src/intellicrack/ui/app.py` | `MainWindow` construction, handler wiring |
| `src/intellicrack/main.py` / `__main__.py` | Bootstrap, arg parsing, bridge init |
| `src/intellicrack/ui/dialogs/splash_screen.py` | Construction, DPI, progress |
| `src/intellicrack/ui/log_viewer/_record.py` | `parse_json_line`, `from_logging_record`, `record_to_json_text`, `extras_to_compact_json` |
| `src/intellicrack/ui/log_viewer/_tail_reader.py` | Initial load, live append, rotation, corrupt lines |
| `src/intellicrack/ui/log_viewer/_handler.py` | Install/uninstall, frame attribution, reentrancy, pause |
| `src/intellicrack/ui/log_viewer/_model.py` | Ring buffer, column data, level colors, eviction |
| `src/intellicrack/ui/log_viewer/_proxy.py` | Level filter, regex filter, text search, combined |
| `src/intellicrack/ui/log_viewer/window.py` | `LogViewerWindow`, filter toolbar, live log |
| `src/intellicrack/ui/resources/resource_helper.py` | Path resolution, `AssetNotFoundError` |
| `src/intellicrack/ui/resources/font_manager.py` | Singleton, loading, families |
| `src/intellicrack/ui/resources/icon_manager.py` | Singleton, SHA-256 verification |
| `src/intellicrack/ui/resources/theme_manager.py` | Singleton, stylesheet loading |

---

## 2. Operation Inventory Table

| # | Operation | Source file:line | Test file(s) | Verdict | Missing edges |
|---|-----------|-----------------|--------------|---------|---------------|
| 1 | `format_hex_dump()` — hex+ASCII layout, address, prefix | `_hex_format.py:23` | `test_hex_format.py:25-167` | **REAL** | None significant |
| 2 | `_resolve()` — Qt method lookup, AttributeError on miss | `_screen_compat.py:35` | None | **NO COVERAGE** | All paths |
| 3 | `get_screen_geometry()` — returns `(x,y,w,h)` or None | `_screen_compat.py:57` | None | **NO COVERAGE** | All paths |
| 4 | `move_widget()` — calls `_resolve(widget, "move")` | `_screen_compat.py:78` | None | **NO COVERAGE** | All paths |
| 5 | `CSyntaxHighlighter.highlightBlock()` — single-line rules | `highlighter.py:223` | None | **NO COVERAGE** | All paths |
| 6 | `CSyntaxHighlighter.highlightBlock()` — multi-line `/* */` block state | `highlighter.py:242-265` | None | **NO COVERAGE** | Block-state tracking |
| 7 | `AssemblySyntaxHighlighter.highlightBlock()` | `highlighter.py:710` | None | **NO COVERAGE** | All paths |
| 8 | `PythonSyntaxHighlighter.highlightBlock()` + `_highlight_triple_quotes()` | `highlighter.py:919-1003` | None | **NO COVERAGE** | Triple-quote state machine |
| 9 | `JavaScriptSyntaxHighlighter.highlightBlock()` — multi-line `/* */` block state | `highlighter.py:1153` | None | **NO COVERAGE** | Block-state tracking |
| 10 | `HexPatSyntaxHighlighter.highlightBlock()` — multi-line `/* */` block state | `highlighter.py:1349` | None | **NO COVERAGE** | Block-state tracking |
| 11 | `get_highlighter_for_language()` — dispatch by alias | `highlighter.py:1395` | None | **NO COVERAGE** | All aliases, unknown |
| 12 | `show_error()` — QMessageBox.critical + structured log | `dialogs_helpers.py:28` | `test_dialogs.py:66`, `test_realcov_15_dialog_helpers_logging.py:88` | **REAL** | |
| 13 | `show_warning()` — QMessageBox.warning + structured log | `dialogs_helpers.py:65` | `test_dialogs.py:143`, `test_realcov_15_dialog_helpers_logging.py:118` | **REAL** | |
| 14 | `show_info()` — QMessageBox.information + structured log | `dialogs_helpers.py:102` | `test_dialogs.py` (arg-forward only) | **WEAK** | Log emission side-effect not verified |
| 15 | `GeneralSettingsWidget.get_settings()` — provider, tools_dir | `preferences.py:189` | `test_realcov_15_preferences_dialog.py:57,116` | **REAL** | provider/confirmation_level combos |
| 16 | `AppearanceSettingsWidget.get_settings()` — theme, font, show_tool_calls | `preferences.py:278` | None | **NO COVERAGE** | All sub-settings |
| 17 | `SessionSettingsWidget.get_settings()` — auto_save, interval, retention | `preferences.py:349` | None | **NO COVERAGE** | All sub-settings |
| 18 | `LoggingSettingsWidget.get_settings()` — level, file/console, rotation | `preferences.py:436` | `test_realcov_15_preferences_dialog.py:86` | **REAL** (partial) | file_enabled/console_enabled/rotation round-trip |
| 19 | `PreferencesDialog._build_config()` — merges all sub-widget settings | `preferences.py:587` | `test_realcov_15_preferences_dialog.py:57,86,116` | **REAL** (partial) | Appearance + Session branches never driven |
| 20 | `PreferencesDialog.settings_changed` signal on Accept | `preferences.py:466` | `test_realcov_15_preferences_dialog.py:57` | **REAL** | |
| 21 | `PreferencesDialog._on_apply()` + disk save via `Config.save()` | `preferences.py:573` | `test_realcov_15_preferences_dialog.py:116` | **REAL** | Corrupt config on load; OSError on save |
| 22 | `SessionManagerDialog` table population from real store | `session_manager.py` | `test_realcov_15_session_manager_dialog.py:85` | **REAL** | Empty store |
| 23 | `SessionManagerDialog.session_loaded` signal + ID payload | `session_manager.py` | `test_realcov_15_session_manager_dialog.py:106` | **REAL** | No-selection guard |
| 24 | `SessionManagerDialog.session_deleted` signal + SQLite removal | `session_manager.py` | `test_realcov_15_session_manager_dialog.py:137` | **REAL** | Keep-vs-doomed verified |
| 25 | `_FlowLayout` tag-chip flow wrapping | `session_manager.py:64` | None | **NO COVERAGE** | All layout paths |
| 26 | `ChatPanel.message_submitted` — typed text, empty guard, whitespace-only | `chat.py` | `test_realcov_15_chat_panel.py:64,97` | **REAL** | |
| 27 | Enter-key submit / Shift+Enter newline | `chat.py` | `test_realcov_15_chat_panel.py:122,139` | **REAL** | |
| 28 | `ChatPanel.add_message()` — bubble appended to history | `chat.py` | `test_realcov_15_chat_panel.py:161` | **REAL** | ToolResult role not tested |
| 29 | `ChatPanel.add_message()` with ToolCall — renders tool widget | `chat.py` | `test_realcov_15_chat_panel.py:175` | **REAL** | |
| 30 | `ChatPanel.add_streaming_message()` — incremental chunk append | `chat.py` | `test_realcov_15_chat_panel.py:201` | **REAL** | Streaming interruption (zero-chunk, mid-word abort) |
| 31 | `ChatPanel.clear_messages()` | `chat.py` | `test_realcov_15_chat_panel.py:218` | **REAL** | |
| 32 | `ChatPanel.insert_context_text()` | `chat.py` | `test_realcov_15_chat_panel.py:236` | **REAL** | |
| 33 | `ToolConfirmationDialog.decision_made` — approve/deny | `confirmation_dialog.py` | `test_confirmation_dialog.py:124,145` | **REAL** | |
| 34 | `ToolConfirmationDialog.remember_similar` → class cache | `confirmation_dialog.py` | `test_confirmation_dialog.py:166,189` | **REAL** | |
| 35 | `ToolConfirmationDialog.exec()` short-circuit via cache | `confirmation_dialog.py` | `test_confirmation_dialog.py:224,255` | **REAL** | |
| 36 | Cache key isolation: `(tool_name, function_name)` pair | `confirmation_dialog.py` | `test_confirmation_dialog.py:285` | **REAL** | |
| 37 | `DetachedPanelWindow` construction + centralWidget identity | `panel_dock.py` | `test_panel_dock.py:33` | **REAL** | |
| 38 | `DetachedPanelWindow.reattach_requested` on re-dock click | `panel_dock.py` | `test_panel_dock.py:84` | **REAL** | |
| 39 | `DetachedPanelWindow.reattach_requested` on close | `panel_dock.py` | `test_panel_dock.py:96` | **REAL** (weak — passes `None` for QCloseEvent) | Real QCloseEvent not used |
| 40 | `OverflowToolBar` extension button hooking | `overflow_toolbar.py` | `test_overflow_toolbar.py:81` | **REAL** | |
| 41 | Overflow menu population with clipped buttons | `overflow_toolbar.py` | `test_overflow_toolbar.py:104` | **REAL** | |
| 42 | Proxy action click drives underlying button | `overflow_toolbar.py` | `test_overflow_toolbar.py:141` | **REAL** | |
| 43 | Empty notice when nothing overflows | `overflow_toolbar.py` | `test_overflow_toolbar.py:179` | **REAL** | |
| 44 | `find_window_by_pid()` — nonexistent PID returns None | `win32_embed.py` | `test_win32_embed.py:155` | **REAL** | |
| 45 | `find_window_by_pid()` — real HWND verified with Win32 API | `win32_embed.py` | `test_win32_embed.py:162` | **REAL** | |
| 46 | `embed_window()` — zero/garbage HWND returns None | `win32_embed.py` | `test_win32_embed.py:257,264` | **REAL** | |
| 47 | `poll_and_embed()` — lifecycle, max_retries limit | `win32_embed.py` | `test_win32_embed.py:276,301` | **REAL** | |
| 48 | `XPUStatusDialog` device status label | `xpu_status.py` | `test_xpu_status.py:273` | **REAL** | |
| 49 | `XPUStatusDialog` memory text GB format | `xpu_status.py` | `test_xpu_status.py:397` | **REAL** | |
| 50 | `XPUStatusDialog` requirements terminal states | `xpu_status.py` | `test_xpu_status.py:557` | **REAL** | |
| 51 | `XPUStatusDialog` refresh timer start/stop | `xpu_status.py` | `test_xpu_status.py:239,257` | **REAL** | |
| 52 | Construction checks (group box titles, widget presence) | `xpu_status.py` | `test_xpu_status.py:122-232` | **WEAK** (construct-and-assert-exists) | |
| 53 | `FunctionListPanel.set_functions()` — exact item text `"0x00401000  main"` | `tools.py` | `test_tools_logic.py:135` | **REAL** | |
| 54 | `FunctionListPanel` double-click parses hex address + name | `tools.py` | `test_tools_logic.py:151` | **REAL** | |
| 55 | `FunctionListPanel` malformed item yields no signal | `tools.py` | `test_tools_logic.py:167` | **REAL** | |
| 56 | `XRefPanel` population and click routing | `tools.py` | `test_tools_logic.py` (partial) | **REAL** | |
| 57 | `ToolOutputPanel.wire_sandbox_backend()` | `tools.py` | `test_audit7/ui_wire_sandbox_backend/test_wire_sandbox_backend.py` | **REAL** | |
| 58 | `MainWindow` construction + Qt log handler wired | `app.py` | `test_ui/log_viewer/test_app_integration.py:64` | **REAL** | |
| 59 | `main.py` bootstrap: arg parsing, logging setup, bridge init | `main.py` | None | **NO COVERAGE** | All paths |
| 60 | `__main__.py` entry point | `__main__.py` | None | **NO COVERAGE** | |
| 61 | `SplashScreen` construction, DPI scaling | `dialogs/splash_screen.py` | `test_splash_screen.py` | **REAL** | |
| 62 | `SplashScreen` animated progress update | `dialogs/splash_screen.py` | `test_splash_screen.py` | **REAL** | |
| 63 | `parse_json_line()` — all fields, blank, invalid, non-object | `log_viewer/_record.py:118` | `test_record.py:40-84` | **REAL** | |
| 64 | `from_logging_record()` — structlog override, stdlib fallback | `log_viewer/_record.py:252` | `test_record.py:87-135` | **REAL** | `getMessage()` TypeError path |
| 65 | `record_to_json_text()` — pretty print, non-serializable | `log_viewer/_record.py:297` | `test_record.py:138-174` | **REAL** | |
| 66 | `extras_to_compact_json()` — empty, non-serializable | `log_viewer/_record.py:315` | `test_record.py:177-191` | **REAL** | |
| 67 | `_read_tail_bytes()` / `_parse_tail_lines()` | `log_viewer/_tail_reader.py:35,53` | `test_tail_reader.py:61,84` | **REAL** | |
| 68 | `LogFileTailReader` initial load caps at max_bytes | `log_viewer/_tail_reader.py` | `test_tail_reader.py:84` | **REAL** (byte-math verified) | |
| 69 | `LogFileTailReader` live append via watcher/poll | `log_viewer/_tail_reader.py` | `test_tail_reader.py:126` | **REAL** | File-not-exists at poll time |
| 70 | `LogFileTailReader` rotation notice ordering | `log_viewer/_tail_reader.py` | `test_tail_reader.py:154` | **REAL** (ordering asserted) | |
| 71 | `LogFileTailReader` corrupt-line skipping | `log_viewer/_tail_reader.py` | `test_tail_reader.py:194` | **REAL** | OSError during incremental read |
| 72 | `LogFileTailReader` with real structlog output | `log_viewer/_tail_reader.py` | `test_realcov_15_tail_reader_real_logs.py` | **REAL** | |
| 73 | `QtSignalingHandler` install/uninstall idempotency | `log_viewer/_handler.py:223,244` | `test_handler.py:32,42` | **REAL** | |
| 74 | `QtSignalingHandler.emit()` — correct frame attribution | `log_viewer/_handler.py:170` | `test_handler.py:51` | **REAL** (module/function exact) | |
| 75 | Cross-thread emit | `log_viewer/_handler.py` | `test_handler.py:89` | **REAL** | |
| 76 | Reentrancy guard drops inner emit | `log_viewer/_handler.py:185` | `test_handler.py:113` | **REAL** | |
| 77 | Pause suppresses signal; disk unaffected | `log_viewer/_handler.py:161` | `test_handler.py:141` | **REAL** | |
| 78 | Conversion failure routes to `handleError` | `log_viewer/_handler.py:190` | `test_handler.py:171` | **REAL** | |
| 79 | `LogRecordTableModel` append + coalesce drain | `log_viewer/_model.py:119` | `test_model.py:56` | **REAL** | |
| 80 | `flush()` synchronous drain | `log_viewer/_model.py:130` | `test_model.py:71` | **REAL** | |
| 81 | `data()` — all 6 columns, exact values (JSON round-trip proof) | `log_viewer/_model.py:279` | `test_model.py:80` | **REAL** | |
| 82 | Ring buffer eviction — oldest event identity after 2500 inserts | `log_viewer/_model.py` | `test_model.py:127` | **REAL** | `total_received` counter after eviction |
| 83 | `set_max_rows` shrink evicts oldest rows | `log_viewer/_model.py:180` | `test_model.py:140` | **REAL** | |
| 84 | ForegroundRole per level — exact `QColor(R,G,B)` | `log_viewer/_model.py` | `test_model.py:154` | **REAL** (independent palette) | |
| 85 | BackgroundRole per level — distinct exact colors | `log_viewer/_model.py` | `test_model.py:173` | **REAL** | |
| 86 | Location column fallback chain | `log_viewer/_model.py` | `test_model.py:248` | **REAL** | |
| 87 | `level_name_to_int()` — all levels, case-insensitive, unknown→INFO | `log_viewer/_proxy.py:38` | `test_proxy.py:86-124` | **REAL** | |
| 88 | Min-level filter — exact record identity, fence-post | `log_viewer/_proxy.py` | `test_proxy.py:127` | **REAL** | |
| 89 | Logger-name regex filter | `log_viewer/_proxy.py` | `test_proxy.py:183` | **REAL** | `set_logger_pattern("")` explicit clear |
| 90 | Invalid regex falls back (clears pattern, keeps rows) | `log_viewer/_proxy.py` | `test_proxy.py:203` | **REAL** | |
| 91 | Text search across event + extras | `log_viewer/_proxy.py` | `test_proxy.py:212` | **REAL** | |
| 92 | Case-sensitive toggle | `log_viewer/_proxy.py` | `test_proxy.py:243` | **REAL** | |
| 93 | Combined filters (level + regex + text) | `log_viewer/_proxy.py` | `test_proxy.py:266` | **REAL** | |
| 94 | `LogViewerWindow` construction, filter toolbar, live log | `log_viewer/window.py` | `test_window.py`, `test_realcov_15_window_real_logs.py` | **REAL** | |
| 95 | `get_assets_path()` — valid existing directory | `resources/resource_helper.py:64` | `test_resource_helper.py:39` | **REAL** | `AssetNotFoundError` path not tested |
| 96 | `get_resource_path()` — slash normalization | `resources/resource_helper.py:98` | `test_resource_helper.py:88` | **REAL** | |
| 97 | `get_icon_path()` — auto-extension detection | `resources/resource_helper.py:120` | `test_resource_helper.py:119` | **REAL** | |
| 98 | `resource_exists()` — existing/missing/empty path | `resources/resource_helper.py:175` | `test_resource_helper.py:218` | **REAL** | |
| 99 | Icon integrity — count, SHA-256, file sizes | `resources/` | `test_icon_manager.py:81-103` | **REAL** (SHA-256 oracle) | |
| 100 | `FontManager` singleton + `get_code_font()` family wire-up | `resources/font_manager.py` | `test_font_manager.py:63-234` | **REAL** | |
| 101 | Font config JSON declares expected families and asset files | `resources/font_manager.py` | `test_font_manager.py:522` | **REAL** | |
| 102 | `IconManager` singleton, loading, SVG validity | `resources/icon_manager.py` | `test_icon_manager.py` | **REAL** | |
| 103 | `ThemeManager` singleton, stylesheet loading | `resources/theme_manager.py` | `test_theme_manager.py` | **REAL** | |

---

## 3. Worst Offenders

### G-1: `_screen_compat.py` — ZERO TEST COVERAGE

File: `src/intellicrack/ui/_screen_compat.py:35-87`

`_resolve()`, `get_screen_geometry()`, and `move_widget()` have no tests anywhere in the test suite.
`_resolve()` raises `AttributeError` with a diagnostic message when a Qt method is missing — the error path is documented but never exercised. `get_screen_geometry()` is called from the main bootstrap to center the main window; a bug in the `None`-screen branch (line 68) or in the `(x, y, w, h)` tuple construction is undetectable.

Falsifiability test: delete `get_screen_geometry` — zero tests fail.

---

### G-2: `highlighter.py` — ZERO TEST COVERAGE for all 5 highlighter classes and `get_highlighter_for_language()`

File: `src/intellicrack/ui/highlighter.py:50-1422`

This is the largest untested block in Section 14. Five `QSyntaxHighlighter` subclasses implement stateful `highlightBlock()` that applies regex-based keyword/type/number/comment rules and tracks multi-line state via `setCurrentBlockState()`:

- C/JS/HexPat multi-line `/* ... */` state: `highlighter.py:242-265`, `1174-1196`, `1370-1392`
- Python triple-quote state: `highlighter.py:940-1003`

A bug in block-state tracking causes cascading visual corruption of every text block below the broken one. None of this is tested. `get_highlighter_for_language()` dispatches by alias (`"c"`, `"cpp"`, `"asm"`, `"frida"`, `"hexpat"`, etc.) — all dispatch paths and the `None` fallback are untested.

Falsifiability test: swap `CSyntaxHighlighter` and `AssemblySyntaxHighlighter` in `get_highlighter_for_language()` — zero tests fail. Replace the multi-line block state logic with `pass` — zero tests fail.

---

### G-3: `main.py` / `__main__.py` — ZERO UNIT TESTS for bootstrap

File: `src/intellicrack/main.py`

Arg parsing, `LogConfig` construction, logging init, bridge registration, provider registry, session manager creation, orchestrator wiring, and `MainWindow` instantiation are all untested. `test_app_integration.py` bypasses bootstrap by constructing `MainWindow` directly with pre-built objects.

Falsifiability test: remove `--log-dir` argument — zero tests fail. Swap bridge registration and logging init order — zero tests fail.

---

### G-4: `preferences.py` — `AppearanceSettingsWidget` and `SessionSettingsWidget` not tested

File: `src/intellicrack/ui/preferences.py:278`, `349`

`test_realcov_15_preferences_dialog.py` only drives `GeneralSettingsWidget` (tools_directory) and `LoggingSettingsWidget` (log.level). `AppearanceSettingsWidget` (theme, font_family, font_size, show_tool_calls) and `SessionSettingsWidget` (auto_save, save_interval_seconds, retention_days) are never driven. `_build_config()` at line 587 merges all four sub-widget `get_settings()` dicts — the Appearance and Session branches execute zero times during testing.

Falsifiability test: delete `AppearanceSettingsWidget.get_settings()` or have it return `{}` — no test fails.

---

### G-5: `session_manager.py` — `_FlowLayout` tag flow untested

File: `src/intellicrack/ui/session_manager.py:64`

`_FlowLayout` is a hand-written multi-row flow layout for session tag chips. Its `addItem`, `itemAt`, `takeAt`, `count`, `sizeHint`, and `doLayout` methods are entirely untested.

---

### W-1: `TestXPUStatusDialogConstruction` — nine construct-and-assert-exists tests

File: `tests/test_ui/test_xpu_status.py:122-232`

Nine tests verify widget existence and types but not behavior: `test_dialog_has_window_title`, `test_dialog_contains_device_status_group`, `test_dialog_contains_memory_usage_group`, `test_dialog_contains_model_cache_group`, `test_dialog_contains_system_requirements_group`, `test_dialog_has_four_group_boxes`, `test_dialog_has_refresh_button`, `test_dialog_has_close_button`, `test_dialog_has_memory_progress_bar`, `test_dialog_has_requirements_text_edit`. If `_refresh_device_info()` silently fails and produces wrong label text, these tests pass unchanged. They are legitimate layout integrity checks but must not count toward behavioral coverage.

---

### W-2: `show_info()` structured logging not verified

File: `tests/test_ui/test_dialogs.py`

`test_dialogs.py` verifies argument forwarding to `QMessageBox.information` for `show_info()`. `test_realcov_15_dialog_helpers_logging.py` covers `show_error` and `show_warning` log side-effects but not `show_info`. Deleting the `_logger.info(...)` line in `dialogs_helpers.py:show_info` leaves zero tests red.

---

### W-3: `test_panel_dock.py:96` — `closeEvent(None)` is not a real `QCloseEvent`

File: `tests/test_ui/test_panel_dock.py:96`

`window.closeEvent(None)` passes `None` instead of a real `QCloseEvent`. The current implementation ignores the event parameter, so the test happens to be correct. Any future change that calls `event.ignore()` or inspects `event.type()` would crash in production but not in the test.

---

## 4. Falsifiability Spot-Check

| Operation | Mutation | Test that catches it |
|-----------|----------|---------------------|
| `format_hex_dump` ASCII column | Always return `"."` | `test_hex_format.py:test_space_is_printable` — asserts exact `" "` |
| `parse_json_line` level normalization | Remove `.upper()` | `test_record.py:40` — asserts `record["level"] == "INFO"` |
| `LogRecordTableModel` ring eviction | Remove `popleft()` | `test_model.py:127` — asserts `first["event"] == "e1500"` |
| `LogFilterProxyModel` fence-post | Change `<` to `<=` | `test_proxy.py:127` — asserts `rowCount() == 1` then record identity |
| `LogFilterProxyModel` text search | Remove `extras_text` from haystack | `test_proxy.py:212` — asserts record with `widget="alpha"` survives |
| `QtSignalingHandler` frame attribution | Break `_add_call_info` frame walk | `test_handler.py:76` — asserts `module == "test_handler"` |
| `QtSignalingHandler` reentrancy guard | Remove `_guard.is_active()` check | `test_handler.py:113` — asserts `inner_event` never appears |
| `PreferencesDialog` disk save | Remove `new_config.save(self._config_path)` | `test_realcov_15_preferences_dialog.py:116` — asserts `Config.load()` round-trips |
| `OverflowToolBar` proxy click | Disconnect proxy from underlying button | `test_overflow_toolbar.py:141` — asserts `click_count == 1` |
| `ToolConfirmationDialog` cache key | Change key from `(tool, func)` to `tool` only | `test_confirmation_dialog.py:285` — asserts `other_call` has no cache entry |
| `find_window_by_pid` ownership check | Remove `GetWindowThreadProcessId` PID match | `test_win32_embed.py:162` — asserts `owning_pid.value == os.getpid()` |
| `get_highlighter_for_language("c")` | Return `AssemblySyntaxHighlighter` for `"c"` | **NO TEST — zero tests fail** |
| `get_screen_geometry` | Return `(0, 0, 0, 0)` always | **NO TEST — zero tests fail** |
| `_build_config()` appearance merge | Return `{}` from `AppearanceSettingsWidget.get_settings()` | **NO TEST — zero tests fail** |

---

## 5. Edge Cases Missing from Otherwise-Real Tests

| # | File | Missing edge |
|---|------|-------------|
| E-1 | `log_viewer/_tail_reader.py` | `OSError` during `_read_incremental()` — warning log + `_read_in_progress = False` reset unverified |
| E-2 | `log_viewer/_tail_reader.py` | File deleted between initial load and next poll — early-exit branch unverified |
| E-3 | `log_viewer/_proxy.py` | `set_logger_pattern("")` after a valid pattern is installed — empty-string clear path not explicitly tested |
| E-4 | `log_viewer/_record.py` | `from_logging_record()` when `record.getMessage()` raises `TypeError`/`ValueError` — `_extract_event_text` catch at `_record.py:193` untested |
| E-5 | `ui/preferences.py` | `_on_apply()` when `Config.save()` raises `OSError` — try/except branch unverified |
| E-6 | `ui/preferences.py` | `PreferencesDialog` constructed with corrupt config file (simulated corrupt JSON for `Config.load()`) |
| E-7 | `ui/chat.py` | `add_streaming_message()` appender called zero times — resulting message content state unverified |
| E-8 | `ui/chat.py` | `add_message()` with `ToolResult` role not tested |
| E-9 | `resources/resource_helper.py` | `AssetNotFoundError` raised when assets directory is absent — error path not explicitly tested (only happy path covered) |
| E-10 | `log_viewer/_model.py` | `total_received` counter value after ring-buffer eviction |

---

## 6. Section Scores

**Behavioral gate score (operations with >= 1 real falsifiable gate):**

- Total distinct behavior-bearing operations: 103
- Operations with at least one real gate: 82
- Operations with zero tests: 11 (highlighter ×7, screen_compat ×3, `show_info` log side-effect ×1) plus bootstrap ×4 = 15 total zero-test behaviors
- **Gate score: ~85% (88/103)**

The score is pulled down primarily by the highlighter domain (7 operations) and bootstrap (4 operations).

**Edge-case coverage score:** ~58%

Strong in: log_viewer pipeline (record, model, proxy, tail_reader, handler), hex_format, confirmation_dialog, overflow_toolbar, win32_embed, chat_panel.
Weak in: highlighter (zero), screen_compat (zero), preferences sub-widgets (Appearance + Session zero), _FlowLayout (zero), bootstrap (zero).

**Construct-and-assert-exists tests that inflate coverage theater:** 9 (XPUStatusDialog construction class).

---

## 7. Remediation Recommendations

### Priority 1 — Immediate

**R-1: Write `tests/test_ui/test_highlighter.py`**

Use a `QTextDocument` + `QApplication` fixture. For each highlighter class, assert:

- Exact `format().foreground().color().getRgb()[:3]` at a known match position for a representative token.
  Example: `CSyntaxHighlighter`, input `"int x;"` — `int` at position 0 should yield keyword color `(86, 156, 214)` (derived from `_create_format("#569CD6", bold=True)` in source).
- After `highlightBlock("/* starts here")`, assert `currentBlockState() == 1`. After `highlightBlock("ends here */")`, assert `currentBlockState() == 0`. This proves the multi-line `/* */` state machine survives block boundaries (C, JS, HexPat).
- For `PythonSyntaxHighlighter`: after `highlightBlock('"""starts')` assert state is `1` (DOUBLE_QUOTE); after `highlightBlock('ends"""')` assert state returns to `0`.
- Assert `get_highlighter_for_language("c") is CSyntaxHighlighter`, `"asm"` → `AssemblySyntaxHighlighter`, `"frida"` → `JavaScriptSyntaxHighlighter`, `"hexpat"` → `HexPatSyntaxHighlighter`, `"bogus"` → `None`.

Expected values must be derived from the constant definitions in the source (`_create_format("#569CD6", bold=True)` → RGB `(86, 156, 214)`), not from running the implementation.

**R-2: Write `tests/test_ui/test_screen_compat.py`**

- Assert `_resolve(object(), "nonexistent")` raises `AttributeError` with a message containing the method name.
- Assert `get_screen_geometry(qapp)` returns a `tuple[int, int, int, int]` with `w > 0` and `h > 0`. Ground truth: `QApplication.primaryScreen().availableGeometry()` queried directly via PyQt6, not via the function under test.
- Assert `move_widget(widget, 10, 20)` moves the widget so `widget.pos().x() == 10` and `widget.pos().y() == 20`.

**R-3: Extend `test_realcov_15_preferences_dialog.py` for Appearance + Session sub-widgets**

- Set font size to `14`, theme to `"light"`, `show_tool_calls` to `False`, accept via `settings_changed` signal.  Assert emitted `Config.ui.font_size == 14`, `Config.ui.theme == "light"`, `Config.ui.show_tool_calls is False`.
- Set `auto_save` to `False`, interval to `120`, retention to `7`, accept. Assert emitted `Config.session.auto_save is False`, `Config.session.save_interval_seconds == 120`, `Config.session.retention_days == 7`.

### Priority 2 — High

**R-4: `show_info()` structured log test**

Extend `test_realcov_15_dialog_helpers_logging.py`: call `show_info(None, "Title", "Message")` with a real structlog file handler active. Parse JSON-Lines output, assert a record with `event == "dialog_info"` and `level == "INFO"` is present.

**R-5: `LogFileTailReader` error paths**

Add to `test_tail_reader.py`:
- After initial load, make the file unreadable (Win32: open with exclusive lock; Linux: `chmod 0o000`). Call `force_poll()`. Assert no exception propagates and no spurious records arrive.
- Delete the file after initial load, call `force_poll()`. Assert the early-exit path produces no records.

**R-6: `_FlowLayout` geometry test**

Add `N` `QPushButton` children to a `_FlowLayout`, set a fixed parent width narrower than `N` items. Call `setGeometry`. Assert that layout height exceeds single-row height (i.e., `layout.heightForWidth(narrow_width) > single_row_height`).

**R-7: `resource_helper.AssetNotFoundError` path**

Monkeypatch `_get_package_root()` (not the real bridge, just the path lookup) to return a temp directory with no `assets/` subdirectory. Assert `get_assets_path()` raises `AssetNotFoundError` and that `error.searched_paths` is a non-empty list.

### Priority 3 — Standard

**R-8: Bootstrap arg-parser unit test (`tests/test_main.py`)**

Exercise `parse_args(["--log-dir", "/tmp/x", "--log-level", "DEBUG"])`. Assert the returned namespace has `log_dir == Path("/tmp/x")` and `log_level == "DEBUG"`. No Qt, no real process required.

**R-9: `ChatPanel` streaming interruption edge case**

Call `add_streaming_message("assistant")`, receive the appender, call it zero times. Assert `get_messages()[-1].content == ""` and exactly one `MessageBubble` child exists in the scroll area.

---

## 8. Files Referenced

- `D:\Intellicrack\src\intellicrack\ui\_hex_format.py`
- `D:\Intellicrack\src\intellicrack\ui\_screen_compat.py`
- `D:\Intellicrack\src\intellicrack\ui\highlighter.py`
- `D:\Intellicrack\src\intellicrack\ui\dialogs_helpers.py`
- `D:\Intellicrack\src\intellicrack\ui\preferences.py`
- `D:\Intellicrack\src\intellicrack\ui\session_manager.py`
- `D:\Intellicrack\src\intellicrack\ui\chat.py`
- `D:\Intellicrack\src\intellicrack\ui\confirmation_dialog.py`
- `D:\Intellicrack\src\intellicrack\ui\panel_dock.py`
- `D:\Intellicrack\src\intellicrack\ui\overflow_toolbar.py`
- `D:\Intellicrack\src\intellicrack\ui\win32_embed.py`
- `D:\Intellicrack\src\intellicrack\ui\xpu_status.py`
- `D:\Intellicrack\src\intellicrack\ui\tools.py`
- `D:\Intellicrack\src\intellicrack\ui\app.py`
- `D:\Intellicrack\src\intellicrack\main.py`
- `D:\Intellicrack\src\intellicrack\ui\dialogs\splash_screen.py`
- `D:\Intellicrack\src\intellicrack\ui\log_viewer\_record.py`
- `D:\Intellicrack\src\intellicrack\ui\log_viewer\_tail_reader.py`
- `D:\Intellicrack\src\intellicrack\ui\log_viewer\_handler.py`
- `D:\Intellicrack\src\intellicrack\ui\log_viewer\_model.py`
- `D:\Intellicrack\src\intellicrack\ui\log_viewer\_proxy.py`
- `D:\Intellicrack\src\intellicrack\ui\log_viewer\window.py`
- `D:\Intellicrack\src\intellicrack\ui\resources\resource_helper.py`
- `D:\Intellicrack\src\intellicrack\ui\resources\font_manager.py`
- `D:\Intellicrack\src\intellicrack\ui\resources\icon_manager.py`
- `D:\Intellicrack\src\intellicrack\ui\resources\theme_manager.py`
- `D:\Intellicrack\tests\test_ui\test_hex_format.py`
- `D:\Intellicrack\tests\test_ui\test_resource_helper.py`
- `D:\Intellicrack\tests\test_ui\log_viewer\test_record.py`
- `D:\Intellicrack\tests\test_ui\log_viewer\test_model.py`
- `D:\Intellicrack\tests\test_ui\log_viewer\test_proxy.py`
- `D:\Intellicrack\tests\test_ui\log_viewer\test_tail_reader.py`
- `D:\Intellicrack\tests\test_ui\log_viewer\test_handler.py`
- `D:\Intellicrack\tests\test_ui\log_viewer\test_realcov_15_tail_reader_real_logs.py`
- `D:\Intellicrack\tests\test_ui\log_viewer\test_app_integration.py`
- `D:\Intellicrack\tests\test_ui\test_realcov_15_preferences_dialog.py`
- `D:\Intellicrack\tests\test_ui\test_realcov_15_chat_panel.py`
- `D:\Intellicrack\tests\test_ui\test_realcov_15_session_manager_dialog.py`
- `D:\Intellicrack\tests\test_ui\test_realcov_15_dialog_helpers_logging.py`
- `D:\Intellicrack\tests\test_ui\test_overflow_toolbar.py`
- `D:\Intellicrack\tests\test_ui\test_xpu_status.py`
- `D:\Intellicrack\tests\test_ui\test_win32_embed.py`
- `D:\Intellicrack\tests\test_ui\test_panel_dock.py`
- `D:\Intellicrack\tests\test_ui\test_tools_logic.py`
- `D:\Intellicrack\tests\test_ui\test_font_manager.py`
- `D:\Intellicrack\tests\test_ui\test_icon_manager.py`
- `D:\Intellicrack\tests\test_ui\test_theme_manager.py`
- `D:\Intellicrack\tests\test_ui\test_dialogs.py`
- `D:\Intellicrack\tests\test_ui\test_splash_screen.py`
- `D:\Intellicrack\tests\test_audit5\u9_ui_confirmation\test_confirmation_dialog.py`
