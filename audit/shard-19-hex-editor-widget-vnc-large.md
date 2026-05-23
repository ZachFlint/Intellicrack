# Shard 19 — hex editor widget + VNC + hex editor large sub-modules

- **Files audited**: 6
- **Total LOC**: 7786
- **Generated**: 2026-05-22T00:00:00Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 4     |
| MEDIUM   | 14    |
| LOW      | 6     |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0 (the `print()` references in `_scripting.py` are user-script names / docstrings, not runtime output from Intellicrack itself)
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 4 (panel.py L1110, hex_editor_widget.py L1578, hex_editor/_scripting.py L608/L829, hex_editor/_scripting.py L1196 — see findings)

## Findings by file

### src/intellicrack/ui/panels/hex_editor/**init**.py — LOC 17

**Logger status**: not present (re-export only)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. Pure re-export module per audit §4 (exempt).

---

### src/intellicrack/ui/panels/hex_editor_widget.py — LOC 2096

**Logger status**: `module-level _logger` (L44)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L35)

**Findings**:

- [HIGH] L1576-1579 — `_do_paste` swallows `except ValueError:` from `bytes.fromhex(stripped)` and silently falls back to UTF-8 encoding. There is no log call for the parse failure even though the user-visible behaviour changes (hex paste becomes byte paste). Fix: `_logger.debug("paste_hex_decode_failed_falling_back", text_len=len(text))` or similar inside the except.
- [MEDIUM] L1417-1457 (`_handle_hex_input`) — public-impacting document mutation (`write_bytes` / `insert_bytes` bridge call into the Rust hexcore document) has no entry or success log, only the failure-path warning. Per §2.3, mutating external/native calls need both intent and outcome logging. Fix: add a `debug` log at entry recording `cursor_offset`, `byte_val`, `_edit_mode`.
- [MEDIUM] L1459-1489 (`_handle_ascii_input`) — same pattern as `_handle_hex_input`; bridge mutation has no entry/success log, only failure-path warnings. Fix similarly.
- [MEDIUM] L1491-1530 (`_do_delete`) — successful deletion via `delete_fn(...)` (hexcore native call) is unlogged at success; only failures are warned. Fix: add `_logger.info("hex_editor_delete_succeeded", offset=..., length=...)` after a successful branch.
- [MEDIUM] L1559-1610 (`_do_paste`) — successful `write_bytes`/`insert_bytes` paste (bridge to hexcore) is unlogged at success; only failures warn. Fix: `_logger.info("hex_editor_paste_succeeded", offset=..., size=len(data), mode=self._edit_mode)`.
- [LOW] L1532-1540 (`_do_undo`) and L1542-1550 (`_do_redo`) — document mutating bridge calls (`undo_fn()` / `redo_fn()`) have no logging at all. These are significant state mutations per §2.4 (lifecycle transition / data history). Fix: add `_logger.info("hex_editor_undo_invoked")` / `redo_invoked` with success boolean.
- [LOW] L582-608 (`set_document`) — public method performing real work (resets cursor, modified set, highlights, scrollbar) only logs at the very end with `_logger.debug("document_set", ...)`. Entry log would not hurt; OK as judgment-call LOW.
- [LOW] L1397 — `status_message.emit(f"...")` uses an f-string. This is a Qt signal emit and the formatting is for human-facing UI text, NOT a log call, so it is acceptable. Listed here only as a confirmation it was reviewed.

---

### src/intellicrack/ui/panels/vnc_widget.py — LOC 1955

**Logger status**: `module-level _logger` (L69)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L31)

**Findings**:

- [MEDIUM] L263-307 (`RFBClient.connect`) — public async network method has solid failure logging (L296) and success logging (L299-306) but no explicit entry log before the `asyncio.open_connection`. Per §2.3, network connect should be logged BEFORE the call so a hang/blocking call is observable. Fix: add `_logger.info("vnc_connecting", host=host, port=port, timeout=connect_timeout)` at L278.
- [MEDIUM] L438-457 (`request_framebuffer_update`) — sends a VNC protocol message on the wire (network write via `self._writer.write` + `drain`) with NO log call. Per §2.3, every protocol exchange should be logged. Fix: `_logger.debug("vnc_request_framebuffer_update", incremental=incremental)`.
- [MEDIUM] L1569-1582 (`send_pointer_event`) — protocol message sent over the network with NO log call. Even debug-level coverage is missing for a per-mouse-move network write. Fix: at minimum `_logger.debug("vnc_pointer_event", x=x, y=y, button_mask=button_mask)` (or rate-limit if too chatty).
- [MEDIUM] L1584-1596 (`send_key_event`) — same as above, key event network writes are unlogged. Fix: `_logger.debug("vnc_key_event", key=key, down=down)`.
- [MEDIUM] L309-323 (`_negotiate_version`) — sends `_RFB_VERSION` over the wire (a protocol exchange) but only logs receipt of the server version (L321); the client write at L322 is not logged. Fix: add `_logger.debug("vnc_client_version_sent", version=_RFB_VERSION.decode().strip())` after the write.
- [MEDIUM] L325-407 (`_negotiate_security`/`_perform_vnc_auth`) — multiple wire writes (L356, L394, L399) with no log statements bracketing them. Some are tied to credential exchange; even at debug level the events ought to be observable. Fix: add `_logger.debug("vnc_security_selected", security_type=...)` and `_logger.debug("vnc_auth_response_sent")`.
- [MEDIUM] L409-436 (`_client_init`) — writes `ClientInit` (L423) and `_PIXEL_FORMAT_32BIT` (L429); none of these network writes are logged. Fix: `_logger.debug("vnc_client_init_sent")` and `_logger.debug("vnc_pixel_format_set", format="BGRX-32")`.
- [MEDIUM] L1598-1608 (`disconnect`) — lifecycle transition (per §2.4) is unlogged at success; only the OSError branch debug-logs. Fix: `_logger.info("vnc_disconnecting")` at entry and `_logger.info("vnc_disconnected")` after close.
- [LOW] L515-530 (`_handle_framebuffer_update`) — high-volume per-frame path; entry/exit logging would be noise. Acceptable as-is.
- [LOW] L730-760 (`_handle_zrle_rect`) / L762-801 (`_handle_tight_rect`) — error paths are well covered (L755/L853/L903) but success of decoded rectangle is unlogged. Acceptable given per-rect volume; LOW.

---

### src/intellicrack/ui/panels/hex_editor/_scripting.py — LOC 1513

**Logger status**: `module-level _logger` (L38)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L34)

**Findings**:

- [HIGH] L1193-1205 (`execute_script` — body of the try/except around `exec(compiled, namespace)`) — runs USER-PROVIDED PYTHON CODE in a sandbox. Per §2.3, this is the most security-sensitive external call in the shard, and per the orchestrator's instructions "script invocation, errors, and completions must all be logged". Currently:
  - There is NO `_logger.info("script_invoked", source_len=len(source))` before `compile`/`exec`.
  - The `except BaseException as exc:` branch at L1196 captures the exception into `error_message` but emits NO log call. The script execution failure is silently buffered into the return dict; only the caller (`_on_script_finished` at L1496) eventually logs `script_execution_error` at WARNING level when the panel renders the traceback — and that happens on the Qt thread, not at the actual failure site.
  - There is no `_logger.info("script_completed", ...)` exit log.
  Fix: add `_logger.info("script_invoked", source_sha256=hashlib.sha256(source.encode()).hexdigest()[:12], source_len=len(source))` at entry; add `_logger.exception("script_execution_failed", error=type(exc).__name__)` inside the `except BaseException` branch (before captures/return); add `_logger.info("script_completed", stdout_len=len(stdout_capture.getvalue()), stderr_len=len(stderr_capture.getvalue()), output_files=len(output_files), had_error=error_message is not None)` before the return.
- [HIGH] L606-610 — `except LookupError as exc:` re-raises with a new LookupError but emits no log statement. Even though the message is propagated, per §2.2 every except block must log. Fix: `_logger.warning("script_search_text_unknown_encoding", encoding=resolved)` before raising.
- [HIGH] L827-830 — `except LookupError as exc:` re-raises without logging. Same fix as above.
- [MEDIUM] L1062 — `resolved.open("w", encoding="utf-8")` — file write open inside the sandboxed script tempdir. No surrounding log call. Per §2.3, file writes must be logged. The caller (`_safe_print`) doesn't log either. Fix: `_logger.info("file_written", path=str(resolved), kind="script_print_output", mode="w")` before opening.
- [MEDIUM] L1112 — `Path(tempfile.mkdtemp(prefix=_SCRIPT_TEMPDIR_PREFIX))` — creates a temp directory for sandboxed script output. Not strictly a Path.mkdir but creates filesystem state. Fix: `_logger.debug("script_sandbox_tempdir_created", path=str(sandbox_dir))`.
- [MEDIUM] L1397-1412 (`_on_load_script`) — public method opens a file dialog and reads the chosen script. Operationally significant per §2.3 (user-provided target path). Entry log missing, success log missing (only OSError logs). Fix: `_logger.info("script_loaded", path=script_path, size=len(content))` after `setPlainText`.
- [MEDIUM] L1432-1438 — `Path(save_path).write_text(...)` — file write inside an exception handler that catches OSError. The `_logger.info("file_written", ...)` at L1426-1431 happens BEFORE the write, so order is correct, but on OSError there's nothing recording the intended path that failed (the path is in the `_logger.exception("script_save_failed")` line but without `path=` kwarg). Fix: change L1438 to `_logger.exception("script_save_failed", path=save_path)`.
- [MEDIUM] L1340 (`worker.start()` in `_on_run_script`) — starts a `GenericCallableWorker` that runs `execute_script` in a background thread. Significant lifecycle transition (§2.4) with no log. Fix: `_logger.info("script_worker_started", has_write_access=isinstance(doc_api, _DocAPI))`.
- [LOW] L74-75 — `except ImportError: _logger.debug(...)` — fine, but in a similar pattern to other modules this is debug-level for an optional import. Acceptable.
- [LOW] L1066-1106 (`execute_script` signature/docstring) — this is the function flagged HIGH above; LOW noted that the docstring claims "Script-level exceptions are caught ... returned via the traceback key" but does not mention logging — once the HIGH fix is applied the docstring would also benefit from noting "and emitted as a `_logger.exception` log call".

Note on L1195: the `# noqa: S102  # nosec B102` comment is for bandit/ruff security rules, NOT for logging suppressions, so it is not flagged per criteria §3.7.

---

### src/intellicrack/ui/panels/hex_editor/_transforms.py — LOC 1070

**Logger status**: `module-level _logger` (L43)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L31)

**Findings**:

- [HIGH] L917-931 (`_on_apply_arithmetic`) — catches `(RuntimeError, OSError, ValueError, TypeError, AttributeError) as exc` from a BRIDGE CALL (`bridge.select_range` + `bridge.apply_arithmetic_to_selection`) and emits `_logger.warning(...)` at L923 WITHOUT including the captured exception. Per §3.6, "Catching exception but using `.error()` / `.warning()` instead of `.exception()` so the traceback is lost" is a HIGH violation. The exception object `exc` is captured (used in the message-box) but its traceback is dropped from logs. Fix: change to `_logger.exception("arithmetic_bridge_failed", operation=op_short, selection_start=sel_start, selection_end=bridge_end)` (no `exc_info` kwarg needed — `.exception` includes it automatically).
- [MEDIUM] L905-912 — `except ValueError:` from `bytes.fromhex(key_hex...)` validation. User gets a dialog but no log. Per §2.2 every except must log. Fix: `_logger.warning("arithmetic_invalid_hex_key", text=key_hex)` before showing dialog.
- [MEDIUM] L451-483 (`_run_single_transform`) — calls `self.document.transform_data(...)` which is the hexcore bridge invocation per §2.3. Failure is logged at L475 but there's no entry log of the intent. Fix: `_logger.debug("transform_single_invoked", node=node_name, offset=offset, length=length)` before L473.
- [MEDIUM] L485-514 (`_on_transform_preview`) — preview path invokes `_run_single_transform` plus `self.document.length()` plus renders a preview. No entry/exit log of the user-visible action. Fix: `_logger.debug("transform_preview_requested", cursor=cursor_offset, len=read_len)` near L502.
- [MEDIUM] L807-824 (`_on_block_copy`) — invokes `self.document.copy_block(...)` (native bridge call) but only logs failure (L819); no entry log of intent, no success log. Same gap is in `_on_block_move` (L826-843) and `_on_block_swap` (L845-863). Fix: add `_logger.info("block_copy_invoke", src=src, length=length, dst=dst)` before the call and `_logger.info("block_copy_complete", ...)` after, mirroring the pattern already present in `_on_block_fill` (L795/L805).
- [LOW] L74-75 — `except ImportError: _logger.debug("transform_pipeline_class_import_unavailable")` — appropriate.
- [LOW] L553-561 — `_logger.info("file_written", path="<document>", ...)` — uses a placeholder path `"<document>"` because the doc isn't a file path; acceptable but consider including `self.file_path` when available so downstream auditors can correlate.

---

### src/intellicrack/ui/panels/hex_editor/panel.py — LOC 1135

**Logger status**: `module-level _logger` (L79)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L40)

**Findings**:

- [HIGH] L1105-1111 (`_refresh_bookmarks_tree`) — `except (AttributeError, ValueError): pass` — silent swallow. Per §2.2 every except must log; bare `pass` is the classic anti-pattern. Fix: `_logger.exception("refresh_bookmarks_tree_failed")` (or `.warning` if expected at startup before doc is loaded).
- [HIGH] L659-676 (`_on_save`) — catches `except OSError as exc:` at L670, shows a warning dialog, but emits NO log call for the file-write failure. This is a save operation (file I/O per §2.3). Fix: `_logger.exception("file_save_failed", path=str(file_path))` before `show_warning`.
- [HIGH] L678-694 (`_on_save_as`) — same pattern: `except OSError as exc:` at L687 with dialog and no log. Fix: `_logger.exception("file_save_as_failed", path=save_path)`.
- [MEDIUM] L588-645 (`load_file`) — public method, performs real work (file open + parsing). The OSError branch at L639 logs `_logger.warning("file_load_failed", path=str(path))` but should be `_logger.exception(...)` since we're inside the except block (per §3.6 — traceback is lost otherwise). Fix: change `.warning` to `.exception` at L640.
- [MEDIUM] L659-676 (`_on_save`) — entry log missing. The `_logger.info("file_saved", path=file_path)` at L676 only fires on the success path. Fix: add `_logger.info("file_save_requested", path=str(file_path) if file_path is not None else None)` near L662.
- [MEDIUM] L967-980 (`save`) — public method that wraps `_on_save` and catches `OSError`. Entry/success log missing; only the exception path logs. Fix: `_logger.info("panel_save_invoked")` at L972 and `_logger.info("panel_save_succeeded")` before `return True`.
- [MEDIUM] L809-820 (`set_bridge`) and L822-883 (`set_state_holder`) — public methods, significant lifecycle wiring (per §2.4: bridge attachment / state holder registration). Neither logs the attachment. Fix: `_logger.info("hex_editor_bridge_attached")` / `_logger.info("hex_editor_state_holder_attached")`.
- [MEDIUM] L713-722 (`goto_offset`) — public method, no log. Borderline trivial-delegation but the offset is a user-visible navigation action. Fix at LOW would also be acceptable. Fix: `_logger.debug("goto_offset_invoked", offset=offset)`.
- [LOW] L752-787 (`_on_send_to_ai`) — emits a context dict to AI; this is an "AI provider call orchestration" event per the orchestrator's interest. Both `except` branches log debug correctly, but the success path doesn't log `_logger.info("ai_context_pushed", cursor=cursor_offset, has_bytes="bytes_at_cursor" in context)`.
- [LOW] L706-711 — `except ValueError: _logger.warning(...)` — acceptable. Reading user-provided text input from the goto field.

---

## Aggregate notes

- **VNC protocol coverage is strong on the receive side** (`handle_server_message`, ZRLE/Tight decompress, raw pixel reads) but weak on the **send side** — every outbound RFB write (version, security selection, auth response, ClientInit, framebuffer-update request, pointer event, key event) goes over the wire without any log statement. Recommend a dedicated "vnc protocol I/O" follow-up pass to add `_logger.debug` symmetrically before each `self._writer.write(...)` so a packet capture can be cross-referenced to the log timeline.
- **The hex editor's mutation flow is consistently asymmetric**: every error path is well-logged, but the success paths of `write_bytes` / `insert_bytes` / `delete_bytes` / `undo` / `redo` in `hex_editor_widget.py` are silent. This is a systemic gap across `_handle_hex_input`, `_handle_ascii_input`, `_do_delete`, `_do_paste`, `_do_undo`, `_do_redo`. Consider a single helper (`_log_mutation`) that the success branches all call.
- **Script execution (the most security-sensitive surface in the shard) has the worst coverage**: `execute_script` neither logs invocation, nor exceptions at the failure site, nor completion. The only log emission for a failed script run is in the Qt thread when the panel renders the traceback, which is too late for forensic timeline reconstruction. Fix this first.
- **`save` / `save_as` file-write failures are unlogged in panel.py** despite the well-established pattern elsewhere of `_logger.exception(...)` on OSError. This is a file-I/O coverage gap per §2.3.
- **One TRY400-style HIGH finding** (`_on_apply_arithmetic`, `_transforms.py:923`) where `_logger.warning` is used inside an except block that doesn't re-raise, losing the traceback. Per project memory, `.warning()` is the correct choice ONLY when re-raising; here we're not.
- **Use of `# noqa: S102  # nosec B102`** at `_scripting.py:1195` is a security-rule suppression for the `exec(...)` call, not a logging suppression, so it is NOT a violation of §3.7. It is the documented sandboxed-script execution path.
- **No `print(...)`, no stdlib `logging`, no `contextlib.suppress`** anywhere in the shard. The canonical `_logger = get_logger(__name__)` pattern is followed in all five non-trivial files.
- **Largest file (`hex_editor_widget.py`, 2096 LOC) was straightforward**: heavy on QPainter rendering (no logging needed) with a well-bounded set of input-handler functions. The audit difficulty here was confirming the symmetric success/failure logging across half a dozen mutating handlers.
