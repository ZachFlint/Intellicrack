# F18 — Silent `except` in `ui/panels/hex_editor/` submodules

## Fix description

Numerous silent-except sites across the hex-editor submodule forest. Many fit the F04 `_invalid_input` helper (UI parse failures); others need targeted debug/warning logs. Two files (`_bookmarks.py`, `_calculator.py`) require F06 module-level `_logger` first.

## Sites to fix

(Sites already covered by F02 [_safe_int_from_str], F04 [_invalid_input], F10 [warning→exception] are NOT repeated here.)

### `src/intellicrack/ui/panels/hex_editor/_base.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 663-664 | `compute_hash()` — `except (ValueError, TypeError, OSError, RuntimeError, ImportError) as exc:` returns formatted error string with no log | `_logger.exception("compute_hash_failed", algo=algo)` before return |

### `src/intellicrack/ui/panels/hex_editor/_widgets.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 447-449 | `_calculate()` — `except ValueError as exc:` sets error label silently | `_logger.warning("custom_crc_invalid_input", error=str(exc))` before early return |

### `src/intellicrack/ui/panels/hex_editor/_hashing.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 96-97 | `_resolve_custom_crc_file_path` — `except (OSError, RuntimeError, ValueError):` `doc_path = None` | `_logger.debug("custom_crc_doc_path_unavailable", error_type=...)` |
| HIGH | 113-115 | Same function — `except OSError: continue` per candidate | `_logger.debug("custom_crc_candidate_unreadable", path=path_str)` |
| HIGH | 143-146 | `_on_custom_crc()` — `except (RuntimeError, OSError, ValueError, AttributeError) as exc:` QMessageBox only | `_logger.warning("custom_crc_length_unavailable", error=str(exc))` |
| HIGH | 264-265 | `_on_repair_pe_checksum()` post-verify — silent except updates label | `_logger.warning("pe_checksum_post_repair_verify_failed", error=str(exc))` |

### `src/intellicrack/ui/panels/hex_editor/_data_inspector.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 327-330 | `_on_decode_text()` — `except (AttributeError, TypeError, ValueError):` `doc_len = 0` silent | `_logger.warning("decode_text_doc_length_unavailable")` |
| HIGH | 337-342 | Same — `except (AttributeError, ValueError, OverflowError) as exc:` sets output field, no log | `_logger.warning("decode_text_failed", encoding=encoding, length=length, error=str(exc))` |
| HIGH | 370-373 | `_on_encode_text` — addressed in F10 (.warning → .exception) |

### `src/intellicrack/ui/panels/hex_editor/_yara.py`

(L273 and L197 are addressed in F04 `_invalid_input` helper — UI input parse.)

### `src/intellicrack/ui/panels/hex_editor/_disassembly.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| LOW | 248-251 | Inner `except (TypeError, ValueError): address_int = 0` fallback | `_logger.debug("disasm_address_unparseable", raw=...)` |

### `src/intellicrack/ui/panels/hex_editor/_sections.py` and `_yara.py`

(Already covered by F04 for the `_on_*_double_clicked` UI parse sites.)

### `src/intellicrack/ui/panels/hex_editor/panel.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 1105-1111 | `_refresh_bookmarks_tree` — `except (AttributeError, ValueError): pass` silent | `_logger.exception("refresh_bookmarks_tree_failed")` (or `.warning` if expected at startup before doc loaded) |
| HIGH | 670 | `_on_save` — `except OSError as exc:` shows warning dialog without log | `_logger.exception("file_save_failed", path=str(file_path))` before `show_warning` |
| HIGH | 687 | `_on_save_as` — same pattern | `_logger.exception("file_save_as_failed", path=save_path)` |

### `src/intellicrack/ui/panels/hex_editor/_templates.py`

All 8 sites are covered by F02 `_safe_int_from_str` helper for PE/ELF struct reads.

| Severity | Lines | Context | Note |
|----------|-------|---------|------|
| MEDIUM | 335-336 | `_on_export_template` — `Path.write_text` logged BEFORE the write (order bug) | Move the success log to AFTER the write succeeds (existing `except` already logs failure) |

### `src/intellicrack/ui/panels/hex_editor/_bookmarks.py`

Requires F06 (module-level `_logger` added) first. Then:

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 74 | `self.document.add_bookmark(...)` no logging | Wrap in try/except + `_logger.info("bookmark_added", offset=cursor_offset, name=name, color=color.name())` on success, `.exception(...)` on failure |
| HIGH | 96 | `self.document.remove_bookmark(index)` no logging | Wrap + `_logger.info("bookmark_removed", index=index, offset=bm_offset, length=bm_length)` |
| HIGH | 89, 106 | `self.document.list_bookmarks()` no logging / no exception handling | Wrap in try/except, log on failure |

### `src/intellicrack/ui/panels/hex_editor/_calculator.py`

Requires F06 (module-level `_logger` added) first. Then all silent except sites (L106, L140, L150, L226, L240) get `_logger.debug(...)` calls per F06's note.

### `src/intellicrack/ui/panels/hex_editor/_comparison.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| LOW | 194-195 | `_cleanup_diff_temp` — `except FileNotFoundError: pass` idempotent cleanup | (Optional) `_logger.debug("diff_temp_already_gone")` |

## Acceptance criteria

- [ ] All HIGH sites above log before silent return / pass / re-raise
- [ ] `_templates.py` L335 ordering bug fixed (success log after the actual write)
- [ ] `_bookmarks.py` mutations wrapped + logged after F06 module-level `_logger` added
- [ ] `_calculator.py` excepts logged after F06 module-level `_logger` added
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
