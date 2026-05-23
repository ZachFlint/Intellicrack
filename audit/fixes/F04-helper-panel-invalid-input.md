# F04 — UI panel input parse: `self._invalid_input` helper

## Fix description

Across the Frida / Ghidra / x64dbg panels (and a few hex-editor submodules), the pattern is:

```python
try:
    addr = int(addr_text, 16)
except ValueError:
    self._console.appendPlainText(f"[-] Invalid address: {addr_text}")
    return
```

The console message is shown to the user but the structured log is silent. Closes 15 HIGH findings via a single shared helper.

## Helper template

Add to `src/intellicrack/ui/panels/base_panel.py`:

```python
class BasePanel(QWidget):
    ...

    def _invalid_input(
        self,
        event: str,
        input_text: str,
        console_msg: str,
        *,
        logger: structlog.stdlib.BoundLogger,
        **context: Any,
    ) -> None:
        """Log a structured user-input parse failure AND surface the message to the panel console.

        Args:
            event: Snake_case event name (e.g. "x64dbg_run_to_invalid_address").
            input_text: The raw input text that failed to parse.
            console_msg: User-facing message (written to the console widget if present).
            logger: Module-level _logger of the calling panel.
            **context: Additional structured kwargs (operation, field name, etc.).
        """
        logger.warning(event, input_text=input_text, **context)
        console = getattr(self, "_console_output", None) or getattr(self, "_console", None) or getattr(self, "_output", None)
        if console is not None:
            console.appendPlainText(console_msg)
```

Use sites become:

```python
try:
    addr = int(addr_text, 16)
except ValueError:
    self._invalid_input(
        "x64dbg_run_to_invalid_address",
        input_text=addr_text,
        console_msg=f"[!] Invalid address: {addr_text}",
        logger=_logger,
    )
    return
```

## Sites to fix

### `src/intellicrack/ui/panels/frida_panel.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 1023 | stalker follow — `int(tid_text)` |
| HIGH | 1683 | `_on_write_memory` — `bytes.fromhex(hex_str)` |
| HIGH | 1711 | `_on_scan_memory` — pattern hex parse |
| HIGH | 2129 | `_on_call_function` — `int(a.strip(), 0)` args parse |

### `src/intellicrack/ui/panels/ghidra_panel.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 980 | `_on_get_data_type` — hex address parse |
| HIGH | 1041 | `_on_set_data_type` — hex address parse |
| HIGH | 1145 | `_parse_address` helper — common silent return None |
| HIGH | 1993 | `_handle_set_color` — color hex parse |
| HIGH | 3091 | `_on_run_script` — JSON params parse |
| HIGH | 3153 | analyzer options JSON parse |

### `src/intellicrack/ui/panels/x64dbg_panel.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 1957 | `_on_run_to` — address parse |
| HIGH | 2008 | `_on_set_ip` — address parse |
| HIGH | 2056 | `_on_add_watchpoint` — address parse |
| HIGH | 2094 | `_on_remove_watchpoint` — id parse |
| HIGH | 2205 | `_on_set_label` — address parse |
| HIGH | 2224 | `_on_set_comment_btn` — address parse |
| HIGH | 2317 | `_on_free_memory` — address parse |
| HIGH | 2403 | `_on_write_memory` — `int(addr_text, 0)` + `bytes.fromhex(data_text)` |
| HIGH | 2423 | `_on_assemble` — address parse |
| HIGH | 2541 | `_on_set_exception_config` — code parse |

### `src/intellicrack/ui/panels/cutter_tabs.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 590 | `HexdumpTab._on_dump` — addr/length parse |

### `src/intellicrack/ui/panels/hex_editor/_search.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 545 | `_on_numeric_search` — numeric input parse |

### `src/intellicrack/ui/panels/hex_editor/_disassembly.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 350 | `_on_disasm_row_double_clicked` — address text parse |

### `src/intellicrack/ui/panels/hex_editor/_sections.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 389 | `_on_string_double_clicked` — offset_text parse |

### `src/intellicrack/ui/panels/hex_editor/_yara.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 273 | `_on_yara_result_double_clicked` — offset_text parse |
| HIGH | 197 | inner loop offset parse (`continue`) |

## Acceptance criteria

- [ ] `_invalid_input` helper added to `BasePanel` with type hints + docstring
- [ ] All 22 sites above use the helper (or call `_logger.warning(...)` directly when the panel doesn't subclass `BasePanel`)
- [ ] User-facing console messages preserved verbatim
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
