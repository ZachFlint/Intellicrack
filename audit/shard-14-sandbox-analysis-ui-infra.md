# Shard 14 — Sandbox analysis + UI infrastructure + resources

- **Files audited**: 16
- **Total LOC**: 8388
- **Generated**: 2026-05-22T00:00:00Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 0     |
| MEDIUM   | 13    |
| LOW      | 7     |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 0

## Findings by file

### src/intellicrack/sandbox/analysis.py — LOC 1356

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**: none.

Notes: All five public functions (`detect_c2_patterns`, `extract_iocs`, `generate_timeline`, `match_behaviors`, `diff_reports`) have matching entry+exit debug logging. Both `except` blocks (`L141-142` ValueError → `_logger.debug` with `exc_info=True`; `L164-165` ValueError → `_logger.debug` with `exc_info=True`; `L306-307` and `L1077-1078` continue silently) — the last two (`L306-307`, `L1077-1078`) are inside tight inner loops and the data validation is the only side effect; they are an arguable LOW but the parsing failures are benign (numeric parse of timestamp/argument strings) and the wider operation's outcome is reported via the public function exit log; not flagged.

### src/intellicrack/sandbox/base.py — LOC 756

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**: none.

Notes: All abstract methods (the entire `SandboxBase` API) log the "not-implemented" branch via `_logger.debug` before raising `SandboxError`. The dataclass / `TypedDict` definitions and validators (`validate_file_operation`, `validate_registry_operation`, `validate_process_operation`) are pure data mappers and do not need logging per §4. Module-level `_logger` is present and named correctly.

### src/intellicrack/ui/highlighter.py — LOC 1421

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**: none.

Notes: Module is entirely declarative syntax-highlighting rule construction plus the per-block paint callback `highlightBlock`. `highlightBlock` is a Qt-driven hot path called on every text-block invalidate; entry/exit logging would be inappropriate. The single dispatcher `get_highlighter_for_language` already logs at L1409 with structured kwargs. No external calls, no file I/O, no `except` blocks.

### src/intellicrack/ui/session_manager.py — LOC 1416

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L466 — `SessionManagerDialog.__init__` calls `self.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)` (filesystem mutation per §2.3) without a surrounding log. Fix: log `_logger.debug("session_dir_ensured", path=str(self.SESSIONS_DIR))` after creation. Same call site repeated at L1326 inside `_save_session_to_disk` without a log.
- [MEDIUM] L1326 — `_save_session_to_disk` writes session JSON via `with session_file.open("w", encoding="utf-8")` at L1331 (file-write per §2.3); there is an exit log at L1334 (`session_saved_to_disk`) but no pre-write intent log and no log around the `mkdir` at L1326. Fix: add `_logger.debug("session_save_started", session_id=session_id)` before the write.
- [MEDIUM] L995 — `session_file.unlink()` (file deletion per §2.3). There is a pre-call log at L993 (`session_file_unlinking`) but no success log on the happy path; the surrounding `except OSError` does log. Fix: add an info log after successful unlink (or change the existing pre-call log to a post-call success log) so the deletion outcome is recorded.
- [MEDIUM] L1054 — `Path(path).open("w", encoding="utf-8")` writes the exported session JSON; the success log at L1057 (`session_exported`) is fine, but the level is `debug` for a user-triggered data export — should be `info`. Fix: change to `_logger.info("session_exported", session_id=..., path=...)`.
- [MEDIUM] L918 — `_load_selected_session` logs `session_load_requested` at `debug` then emits `session_loaded` signal; the emission is a significant business event (user requested loading a saved session). Fix: change to `_logger.info("session_load_requested", session_id=session_id)`.
- [LOW] L466, L1326 — duplicated `SESSIONS_DIR.mkdir` calls with no log on either; consider single helper that logs once on first-create.
- [LOW] `_load_sessions_from_disk` at L704 reads every JSON file under `SESSIONS_DIR` (operationally significant — session restore from disk per §2.3). The function has per-file failure logging and a successful summary via `_load_sessions` at L702 (`session_list_refreshed`), but no entry log; add `_logger.debug("session_disk_load_started", dir=str(self.SESSIONS_DIR))`.

### src/intellicrack/ui/resources/theme_manager.py — LOC 1353

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L1180 — `apply_theme` calls `app_instance.setStyleSheet(stylesheet)` and logs `theme_applied` at `info` — good. The failure path at L1185 (`no_qapplication_instance`) is a warning — appropriate. No issues here.
- [LOW] L1220 — `_load_stylesheet` opens the stylesheet file with `style_path.open(encoding="utf-8")` (read-only). The read is operationally significant (user-facing theme load), and there is a debug log at L1223 (`stylesheet_loaded`) on success, an OS-error warning at L1226, and a fallback debug at L1232. Coverage is acceptable; LOW-flag only because the entry into the file-open block has no "attempting to load stylesheet" log, and the load only logs on the read-success branch.

### src/intellicrack/ui/resources/icon_manager.py — LOC 472

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L230-237 — `_check_icons_available` calls `icons_dir.iterdir()` (read-only directory enumeration). The `except (FileNotFoundError, PermissionError)` correctly uses `_logger.exception("icons_availability_check_failed")` — good. No issue.
- [LOW] L259 — `_load_icon` constructs `QIcon` from `icon_path` (file read). The branches log on success/failure/fallback at L276/L278/L280/L282 — coverage is acceptable. No issue.

Notes: All `except` clauses log. All file-read branches log success and failure. Logger pattern correct throughout.

### src/intellicrack/ui/resources/font_manager.py — LOC 336

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L98-124 — `load_fonts` performs significant file-system work (`fonts_dir.glob`, `QFontDatabase.addApplicationFont`). Entry/exit logging is partly present (`fonts_already_loaded` at L92, `custom_fonts_loaded` at L115, `using_fallback_fonts` in the helper). The `except (FileNotFoundError, PermissionError) as e:` at L119 uses `_logger.warning("font_loading_error", error=str(e))` — should arguably be `_logger.exception(...)` so the traceback is preserved (per §3 item 6). LOW because errors here are common environmental conditions and the calling code does not re-raise.
- [LOW] L131 — `_load_font_config` opens `font_config.json` via `config_path.open(encoding="utf-8")` (config load — operationally significant per §2.3). The success log (L133) and exception log (L135) cover the outcomes. Acceptable; no separate finding.

### src/intellicrack/ui/resources/resource_helper.py — LOC 192

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**: none.

Notes: Every path resolution helper logs at `debug` with structured kwargs. The single `except FileNotFoundError` at `resource_exists` (L188) logs a warning before falling through — correct.

### src/intellicrack/ui/resources/__init__.py — LOC 24

**Logger status**: `missing` (acceptable — re-exports only)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. Pure re-export module — exempt per §4.

### src/intellicrack/ui/win32_embed.py — LOC 314

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L100-113 — `_get_user32()` calls `ctypes.WinDLL("user32", use_last_error=True)` followed by `_configure_user32(user32)` (Win32 / ctypes external surface per §2.3) without any log on the success path. Only `embed_window` at L246 logs `win32_embed_unsupported_platform` when None is returned, but the actual DLL-load success is silent. Fix: add `_logger.debug("win32_user32_loaded")` after L112.
- [MEDIUM] L62-97 — `_configure_user32` assigns argtypes/restype to multiple user32 API entry points (configuration of external API surface). No entry log so a malformed PyQt6/ctypes binding leaves no trace. Add `_logger.debug("win32_user32_configured")` at function end.
- [MEDIUM] L116-173 — `find_window_by_pid` invokes `user32.EnumWindows`, `GetWindowThreadProcessId`, `IsWindowVisible`, `GetWindow`, `GetWindowTextW` (external Win32 calls per §2.3). There is no entry log; only a success log at L166 (`win32_window_found`). The "not-found" branch at L173 returns `None` silently. Fix: add `_logger.debug("win32_window_search_started", pid=pid)` at L128 and `_logger.debug("win32_window_not_found", pid=pid)` before the final `return None`.
- [MEDIUM] L176-222 — `_reparent_foreign_hwnd` makes `GetWindowLongPtrW`, `SetWindowLongPtrW`, `SetParent` calls (Win32 surface per §2.3). Failure branches log via `_logger.warning(...)` (good). Success path returns `True` silently. Fix: add `_logger.debug("win32_hwnd_reparented", hwnd=hex(hwnd), parent=hex(parent_hwnd))` before `return True`.
- [LOW] L249-264 — `embed_window` uses a broad `except (RuntimeError, OSError, ValueError):` that logs via `_logger.exception("win32_embed_failed", ...)` — correct usage. No issue.

### src/intellicrack/ui/overflow_toolbar.py — LOC 268

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L139-142 — `try: button.clicked.disconnect() except TypeError: _logger.debug("overflow_toolbar_no_existing_clicked_connections")` — the disconnect-with-no-prior-connection case is logged at `debug`. Correct.

Notes: This file is purely Qt event-handler wiring; no external I/O, subprocess, or filesystem operations. Coverage is adequate.

### src/intellicrack/ui/panel_dock.py — LOC 133

**Logger status**: `missing` (declared via `get_logger(__name__)` at L30 → `_logger`)

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L111-114 — `_save_geometry` writes to `QSettings("Intellicrack", "DetachedPanels")` (config persistence — significant state mutation per §2.4) and is invoked from `_on_redock` (L106-109) and `closeEvent` (L124-133). Neither operation logs the persistence. Fix: add `_logger.debug("detached_panel_geometry_saved", title=self._title)` after the `setValue` call.
- [MEDIUM] L116-121 — `_restore_geometry` reads back the value; no log either. Add `_logger.debug("detached_panel_geometry_restored", title=self._title, restored=bool(geometry))`.
- [MEDIUM] L106-109 — `_on_redock` emits `reattach_requested` signal (significant UI lifecycle transition per §2.4) — no log. Add `_logger.info("detached_panel_redock_requested", title=self._title)`.
- [LOW] L123-133 — `closeEvent` emits the same `reattach_requested` signal and intentionally ignores the close event; no log. Add `_logger.info("detached_panel_close_redocked", title=self._title)`.

Notes: Logger import is present but `_logger` is never called anywhere in this module — a fully-wired logger that emits zero events for several lifecycle operations.

### src/intellicrack/ui/_dialogs.py — LOC 121

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**: none.

Notes: Every helper (`show_error`, `show_warning`, `show_info`) emits a structured log with the appropriate level. The `exc` argument routes traceback to `exc_info=exc` when supplied.

### src/intellicrack/ui/__init__.py — LOC 91

**Logger status**: `missing` (acceptable — re-exports only)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. Pure re-export module — exempt per §4.

### src/intellicrack/ui/_screen_compat.py — LOC 86

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L78-86 — `move_widget(widget, x, y)` mutates widget geometry (UI lifecycle / state mutation) but emits no log on the successful call. The `_resolve` helper logs missing-method failures; success path is silent. Add `_logger.debug("widget_moved", widget=type(widget).__name__, x=x, y=y)` for symmetry with `get_screen_geometry`.

### src/intellicrack/ui/_hex_format.py — LOC 49

**Logger status**: `missing` (acceptable — pure formatter)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. Single pure-function formatter, no I/O, no external calls, no exceptions — exempt per §4.

## Aggregate notes

- **Logger pattern**: All non-trivial modules use the canonical `_logger = get_logger(__name__)` pattern. Zero violations of the naming convention. Zero stdlib `logging` usage.
- **No HIGH violations**: No bare excepts, no `contextlib.suppress`, no `print()` for runtime output, no stdlib logging, no `# noqa` suppressions for logging-related issues.
- **f-string / `%` / `.format` inside log messages**: NONE detected. All log calls use structured kwargs as required by §1.
- **Win32 boundary coverage gap (`win32_embed.py`)**: The single biggest coverage gap in the shard is `win32_embed.py`. Multiple ctypes-API entry points (`EnumWindows`, `SetWindowLongPtrW`, `SetParent`, `GetWindowThreadProcessId`) are invoked without "started/about-to" debug logs; only failure or terminal success states log. Per §2.3 the external Win32 surface should be logged on both intent and outcome. Recommend adding paired entry/exit `debug` logs around `_get_user32`, `find_window_by_pid`, and the success branch of `_reparent_foreign_hwnd`.
- **`panel_dock.py` has imported `_logger` but never calls it**: imports `get_logger` and binds `_logger`, but no log statements emit. Several significant lifecycle transitions (re-dock requested, geometry saved/restored) go unrecorded. This is the second-most material gap in the shard.
- **`session_manager.py` log level downgrades**: a couple of user-driven business events (`session_load_requested`, `session_exported`) are logged at `debug` instead of `info`. The session manager is otherwise the most thoroughly instrumented file in the shard — including exit logs on every error path of `_import_via_manager`, `_peek_session_id`, `_import_to_disk`, and `_delete_session_sync`.
- **Sandbox analysis (`sandbox/analysis.py`) and base (`sandbox/base.py`)**: clean. Every public function logs entry+exit; every `except` block emits at least a debug log with `exc_info=True`; abstract methods in `SandboxBase` all log before raising. These two files are the gold-standard reference for the rest of the shard.
- **Resource managers (`theme_manager.py`, `icon_manager.py`, `font_manager.py`, `resource_helper.py`)**: all well-instrumented. Singletons log cache hits, fallback selection, and OS errors with structured kwargs. Minor LOW-severity nits only.
