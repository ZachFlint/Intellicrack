# F24 — `Session` dataclass mutator logs

## Fix description

The `Session` dataclass in `src/intellicrack/core/session.py` is mutated both by `Orchestrator` (which logs) and by direct callers (which don't log uniformly). Per §2.4 "session updates" must be logged. Adding logging at the data-class layer ensures every mutation is recorded exactly once.

## Sites to fix

`src/intellicrack/core/session.py`:

| Severity | Lines | Method | Suggested log |
|----------|-------|--------|---------------|
| MEDIUM | 158-167 | `Session.add_binary()` | `_logger.debug("session_binary_added", session_id=self.id, binary_name=binary.name)` |
| MEDIUM | 168-175 | `Session.add_message()` | `_logger.debug("session_message_added", session_id=self.id, role=message.role)` |
| MEDIUM | 177-184 | `Session.add_patch()` | `_logger.info("session_patch_added", session_id=self.id, patch_id=patch.id)` (patches are significant; info-level) |
| MEDIUM | 186-194 | `Session.add_bridge_analysis()` | `_logger.debug("session_bridge_analysis_added", session_id=self.id, binary_name=binary_name)` |
| MEDIUM | 207-220 | `Session.set_tool_state()` | `_logger.debug("tool_state_set", tool=state.tool.value, connected=state.connected, attached=state.process_attached)` |
| MEDIUM | 222-235 | `Session.clear_tool_state()` | `_logger.debug("tool_state_cleared", tool=...)` |
| MEDIUM | 237-256 | `Session.add_tag()` | `_logger.debug("session_tag_added", session_id=self.id, tag=tag)` |
| MEDIUM | 258-273 | `Session.remove_tag()` | `_logger.debug("session_tag_removed", session_id=self.id, tag=tag)` |
| MEDIUM | 1170-1191 | `SessionManager.import_json()` | `_logger.info("session_import_requested", path=str(path), replace=replace)` at L1183 |
| MEDIUM | 1226-1231 | `SessionManager._start_auto_save()` | `_logger.debug("autosave_task_started", interval=self.save_interval)` after `asyncio.create_task(...)` |
| LOW | 1049-1059 | `SessionManager.get()` | Add entry/exit logs |
| LOW | 1117-1126 | `SessionManager.list_sessions()` | Add entry log |
| LOW | 1128-1137 | `SessionManager.search_by_tag()` | Add entry log |

## Acceptance criteria

- [ ] All 8 `Session` mutator methods log on success
- [ ] `SessionManager.import_json` logs at entry
- [ ] `_start_auto_save` logs the background task creation
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
- [ ] No double-logging from `Orchestrator` callers (verify by inspection: `Orchestrator.add_patch` at orchestrator.py L2305 currently emits `patch_added` — adjust to avoid duplication, e.g., orchestrator log mentions caller intent, dataclass log records the actual mutation)
