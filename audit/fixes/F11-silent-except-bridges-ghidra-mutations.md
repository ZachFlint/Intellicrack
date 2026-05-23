# F11 — Silent `except` in `bridges/ghidra.py` mutation methods

## Fix description

14 public mutation methods catch a broad `except Exception as e:` and re-raise as `ToolError` **without first logging**. The pattern looks like a copy/paste oversight: nearly all equivalent verified-write methods (e.g. `rename_function`, `add_comment`, `set_label`, `create_bookmark`, `add_reference`, `create_equate`, `set_program_metadata`) DO log via `_logger.warning(...)` before the re-raise. The 14 below should mirror that pattern.

## Fix template

Before:

```python
try:
    result = self._call_jython(...)
except Exception as e:
    raise ToolError(f"create_function failed: {e}") from e
```

After:

```python
try:
    result = self._call_jython(...)
except Exception as e:
    _logger.warning("ghidra_create_function_failed", address=hex(address), error=str(e))
    raise ToolError(f"create_function failed: {e}") from e
```

## Sites to fix

`src/intellicrack/bridges/ghidra.py`:

| Severity | Lines | Method | Context kwargs |
|----------|------:|--------|----------------|
| HIGH | 3589-3592 | `create_function` | `address=hex(address)` |
| HIGH | 3721-3724 | `edit_function_signature` | `address=hex(address), new_name=name, return_type=return_type, calling_convention=calling_convention` |
| HIGH | 3770-3773 | `set_function_variable_type` | `func_address=hex(func_address), var_name=var_name, new_type=new_type` |
| HIGH | 3832-3835 | `define_structure` | `struct_name=name` |
| HIGH | 3921-3924 | `apply_structure_at` | `address=hex(address), struct_name=struct_name` |
| HIGH | 4355-4357 | `undo` | (no extra context — log alone) |
| HIGH | 4380-4382 | `redo` | (no extra context — log alone) |
| HIGH | 5109-5111 | `create_namespace` | `namespace_name=name, parent=parent` |
| HIGH | 5685-5687 | `create_data_type` | `type_name=name, type_kind=type_kind, category=category` |
| HIGH | 5731-5733 | `create_data` | `address=hex(address), data_type=data_type` |
| HIGH | 5792-5794 | `configure_analysis` | `analyzer=analyzer_name, enabled=enabled` |
| HIGH | 5957-5959 | `create_memory_block` | `block_name=name, start=hex(start)` |
| HIGH | 6636-6638 | `add_external_function` | `library=library, func_name=name, address=hex(address) if address is not None else None` |
| HIGH | 6664-6668 | `create_overlay_space` | `overlay_name=name` |

Additionally:

| Severity | Line | Method | Fix |
|----------|-----:|--------|-----|
| LOW | 4192 | `write_bytes` `except ValueError as exc:` raises `ToolError` without log | Add `_logger.debug("ghidra_write_bytes_invalid_hex", error=str(exc))` before raise |

## Note on Jython payload exceptions

Per the shard 04 report, ~13 `except` clauses appearing inside triple-quoted Jython script strings (e.g. L2029, L2441, L4220, L4228, L4809, L4817, L4833, L4836, L4847, L4853, L5875, L6108, L6197, L6200, L6332, L6338, L6358) are inside payloads that execute in Ghidra's JVM, not the Python process. **Do NOT modify those** — they're outside scope.

## Acceptance criteria

- [ ] All 14 HIGH mutation method except blocks updated with a `_logger.warning(...)` call before re-raise
- [ ] L4192 LOW fix applied
- [ ] No new `except Exception:` introduced
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
- [ ] Spot-check: trigger one mutation failure (e.g. invalid struct definition) and verify the warning event appears in the log
