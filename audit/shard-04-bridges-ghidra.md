# Shard 04 — bridges/ghidra.py

- **Files audited**: 1
- **Total LOC**: 7256
- **Generated**: 2026-05-22T00:00:00Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 14    |
| MEDIUM   | 23    |
| LOW      | 4     |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 14 (in this single file)

## Findings by file

### src/intellicrack/bridges/ghidra.py — LOC 7256

**Logger status**: `module-level _logger` (L63: `_logger = get_logger(__name__)`)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L42)

**Notes on scope**:

- The file uses extensive Jython script strings transmitted via the
  `ghidra_bridge` RPC. `except` clauses, `print`-like calls, and similar
  inside triple-quoted Jython payloads run inside Ghidra's embedded JVM
  (not in the Python process) and are therefore NOT subject to the
  Intellicrack logging policy. Examples that are intentionally excluded
  from findings: L2029 (metadata extract Jython), L2441/L4220/L4228
  (decompile / write-bytes jarray Jython), L4809/L4817/L4833/L4836/
  L4847/L4853 (PDB/DWARF Jython), L5875 (decompiler opts Jython),
  L6108/L6197/L6200/L6332/L6338/L6358 (program tree / properties /
  colorize Jython).
- No `print()`, no `contextlib.suppress`, no stdlib `logging`, no
  `# noqa` / `# type: ignore` / `# pyright: ignore`. Logger calls use
  structured kwargs throughout; no f-strings or `%`/`.format()` inside
  log message arguments.
- Most error paths follow the documented project pattern of
  `_logger.warning(...) ; raise ToolError(...) from e` (TRY400-compatible
  re-raise) and `_logger.exception(...) ; raise` for genuine catch-and-
  rethrow. Those are not flagged.

**Findings**:

#### HIGH — `except` block(s) with no log call (silent failure)

- [HIGH] L3589-3592 — `create_function`: `except Exception as e:` raises
  `ToolError` without any log call. Fix: add
  `_logger.warning("ghidra_create_function_failed", address=hex(address), error=str(e))`
  before the raise.
- [HIGH] L3721-3724 — `edit_function_signature`: `except Exception as e:`
  with no log. Variables in scope: `address`, `name`, `return_type`,
  `calling_convention`. Fix: add
  `_logger.warning("ghidra_edit_function_signature_failed", address=hex(address), new_name=name, error=str(e))`.
- [HIGH] L3770-3773 — `set_function_variable_type`: `except Exception as e:`
  with no log. Variables in scope: `func_address`, `var_name`, `new_type`.
  Fix: add `_logger.warning("ghidra_set_function_variable_type_failed", func_address=hex(func_address), var_name=var_name, error=str(e))`.
- [HIGH] L3832-3835 — `define_structure`: `except Exception as e:`
  with no log. Variables in scope: `name`, `fields`. Fix: add
  `_logger.warning("ghidra_define_structure_failed", struct_name=name, error=str(e))`.
- [HIGH] L3921-3924 — `apply_structure_at`: `except Exception as e:`
  with no log. Variables in scope: `address`, `struct_name`. Fix: add
  `_logger.warning("ghidra_apply_structure_at_failed", address=hex(address), struct_name=struct_name, error=str(e))`.
- [HIGH] L4355-4357 — `undo`: `except Exception as e:` with no log.
  Fix: add `_logger.warning("ghidra_undo_failed", error=str(e))`.
- [HIGH] L4380-4382 — `redo`: `except Exception as e:` with no log.
  Fix: add `_logger.warning("ghidra_redo_failed", error=str(e))`.
- [HIGH] L5109-5111 — `create_namespace`: `except Exception as e:` with no
  log. Variables in scope: `name`, `parent`. Fix: add
  `_logger.warning("ghidra_create_namespace_failed", namespace_name=name, parent=parent, error=str(e))`.
- [HIGH] L5685-5687 — `create_data_type`: `except Exception as e:` with no
  log. Variables in scope: `name`, `type_kind`, `category`. Fix: add
  `_logger.warning("ghidra_create_data_type_failed", type_name=name, type_kind=type_kind, error=str(e))`.
- [HIGH] L5731-5733 — `create_data`: `except Exception as e:` with no log.
  Variables in scope: `address`, `data_type`. Fix: add
  `_logger.warning("ghidra_create_data_failed", address=hex(address), data_type=data_type, error=str(e))`.
- [HIGH] L5792-5794 — `configure_analysis`: `except Exception as e:` with
  no log. Variables in scope: `analyzer_name`, `enabled`, `options`. Fix:
  add `_logger.warning("ghidra_configure_analysis_failed", analyzer=analyzer_name, enabled=enabled, error=str(e))`.
- [HIGH] L5957-5959 — `create_memory_block`: `except Exception as e:` with
  no log. Variables in scope: `name`, `start`, `size`, `permissions`. Fix:
  add `_logger.warning("ghidra_create_memory_block_failed", block_name=name, start=hex(start), error=str(e))`.
- [HIGH] L6636-6638 — `add_external_function`: `except Exception as e:`
  with no log. Variables in scope: `library`, `name`, `address`. Fix: add
  `_logger.warning("ghidra_add_external_function_failed", library=library, func_name=name, error=str(e))`.
- [HIGH] L6664-6668 — `create_overlay_space`: `except Exception as exc:`
  with no log (ToolError re-raise above this except is a no-op pass-through;
  the generic Exception path does not log). Variables in scope: `name`.
  Fix: add `_logger.warning("ghidra_create_overlay_space_failed", overlay_name=name, error=str(exc))`.

#### MEDIUM — Missing entry logging on public methods doing real work

The following public methods dispatch non-trivial Jython RPC payloads to
Ghidra and parse the responses, but have no entry-level log statement
recording the call intent (only the error-path or "not connected" branch
is logged). Per §2.1 each should have a `_logger.debug(...)` or
`_logger.info(...)` at the start of the happy path with relevant context.

- [MEDIUM] L2298 — `get_function(address)`: no entry log. Add
  `_logger.debug("ghidra_get_function_started", address=hex(address))`.
- [MEDIUM] L2392 — `decompile(address)`: no entry log. Add
  `_logger.debug("ghidra_decompile_started", address=hex(address))`.
- [MEDIUM] L2493 — `disassemble(address, count)`: no entry log. Add
  `_logger.debug("ghidra_disassemble_started", address=hex(address), count=count)`.
- [MEDIUM] L2561 — `get_xrefs_to(address)`: no entry log.
- [MEDIUM] L2609 — `get_xrefs_from(address)`: no entry log.
- [MEDIUM] L2685 — `search_strings(pattern, encoding)`: no entry log.
- [MEDIUM] L3081 — `get_imports()`: no entry log.
- [MEDIUM] L3129 — `get_exports()`: no entry log.
- [MEDIUM] L3176 — `get_data_type(address)`: no entry log.
- [MEDIUM] L3379 — `get_labels(address, radius)`: no entry log.
- [MEDIUM] L3515 — `get_bookmarks(category)`: no entry log.
- [MEDIUM] L3837 — `get_structures(filter_name)`: no entry log.
- [MEDIUM] L3931 — `get_memory_map()`: no entry log.
- [MEDIUM] L3973 — `get_call_graph(address, depth)`: no entry log.
- [MEDIUM] L4070 — `get_segments()`: no entry log.
- [MEDIUM] L4115 — `get_program_info()`: no entry log.
- [MEDIUM] L5030 — `get_relocations()`: no entry log.
- [MEDIUM] L5113 — `get_namespaces()`: no entry log.
- [MEDIUM] L5247 — `get_equates()`: no entry log.
- [MEDIUM] L5286 — `search_symbols(name, symbol_type)`: no entry log.
- [MEDIUM] L5531 — `get_calling_conventions()`: no entry log.
- [MEDIUM] L6018 — `get_all_comments()`: no entry log.
- [MEDIUM] L6069 — `get_program_tree()`: no entry log.

(Public methods with entry logs that ARE compliant include `analyze`,
`get_functions`, `load_binary`, `search_bytes`, `rename_function`,
`add_comment`, `set_label`, `create_bookmark`, `create_function`,
`delete_function`, `edit_function_signature`, `set_function_variable_type`,
`define_structure`, `apply_structure_at`, `write_bytes`, `read_bytes`,
`undo`, `redo`, `get_pcode`, `get_basic_blocks`, `get_slice`,
`get_callers`, `get_register_value`, `import_debug_info`, `add_reference`,
`delete_reference`, `create_equate`, `get_stack_frame`,
`get_function_body`, `get_call_tree`, `get_instruction_flow`,
`create_data_type`, `create_data`, `configure_analysis`,
`set_decompiler_options`, `create_memory_block`, `get_comments`,
`get_properties`, `diff_programs`, `set_color`, `set_program_metadata`,
`get_thunk_info`, `get_external_references`, `add_external_function`,
`create_overlay_space`, `add_bookmark`, `remove_bookmark`, `add_label`,
`remove_label`, `add_thunk`, `remove_thunk`, `add_external_reference`,
`remove_external_reference`, `execute_script`, `execute_script_with_params`,
`set_port`, `attach_remote_bridge`, `initialize`, `shutdown`,
`is_available`, `start_headless`, `create_bridge_script`.)

#### LOW — Other observations

- [LOW] L4192 — `write_bytes`: `except ValueError as exc:` raises
  `ToolError` without a log call. The validation failure produces an
  immediate `ToolError` and `data` is in scope. Fix: add
  `_logger.debug("ghidra_write_bytes_invalid_hex", error=str(exc))` (or
  `warning`) before the raise.
- [LOW] L1441 — `is_available` logs at `info` level for what is a
  trivial availability probe; `debug` would be a better fit. Minor
  level mismatch.
- [LOW] L1836 — `create_bridge_script` logs `ghidra_create_bridge_script_started`
  at info; debug would be more appropriate for an internal helper-style
  wrapper that simply delegates to `_create_bridge_script`. Minor.
- [LOW] L1253 — `set_port` logs an "operation started" event at info
  for a simple attribute assignment with no meaningful work. Debug
  would be more appropriate; or pair with an exit/confirm log if info
  is intended.

#### Subprocess / Socket / File I/O coverage notes (per §2.3)

- L1514 (`Popen` for Ghidra headless): Surrounded by
  `_logger.info("ghidra_headless_starting", ...)` at L1498 (before) and
  exit-side wiring through `process_manager.register(...)` plus
  `_logger.info("ghidra_headless_connected", ...)` at L1550. Compliant.
- L1720 (`socket.socket` + `connect_ex` in `_wait_for_bridge_port`):
  Each poll attempt logs `ghidra_bridge_port_polling` (L1734) and a
  successful connect logs `ghidra_bridge_port_ready` (L1725). Compliant.
- L1784 (`tempfile.mkdtemp`) + L1798 (`script_path.write_text`): Both
  wrapped with logs before and after (L1791 pre-write, L1821 post-
  verify, L1786/L1800/L1807 on errors). Compliant.
- L1422 (`script_path.unlink`) + L1429 (`parent.rmdir`): Logs on error
  path only (L1424, L1433). The success path of a cleanup helper is a
  reasonable silent operation; not flagged.

## Aggregate notes

- The file is largely well-instrumented. `_logger` is used consistently
  with structured kwargs throughout, with zero f-string or
  `%`/`.format`-style violations inside log calls.
- The dominant HIGH issue is a recurring pattern in 14 public mutation
  methods that catch a broad `Exception as e:` and re-raise as
  `ToolError` without first logging the swallowed traceback. Every one
  of these has variables in scope that would make excellent structured
  context. The pattern looks like a copy/paste oversight: nearly all
  the equivalent verified-write methods (e.g. `rename_function`,
  `add_comment`, `set_label`, `create_bookmark`, `add_reference`,
  `create_equate`, `set_program_metadata`) DO log via
  `_logger.warning(...)` before the re-raise. The remediated methods
  should mirror that pattern.
- The dominant MEDIUM issue is "read-only" `get_*` accessors that
  dispatch significant Jython RPC payloads but have no positive entry
  log. They DO emit error logs in the failure path, so observability
  is partial. Adding a single
  `_logger.debug("ghidra_<method>_started", ...)` line at the top of
  each would close the gap. ~23 such methods.
- Many `except` blocks correctly use `_logger.exception(...)` (full
  traceback) when the exception is logged-and-rethrown via a different
  exception type; the project memory rule about `.warning()` instead of
  `.error()` for re-raise patterns is honored where applicable.
- No use of stdlib `logging`, no `print()`, no `contextlib.suppress`,
  no `noqa`/`type: ignore`/`pyright: ignore`. No structured-kwargs
  violations. The file's overall logger hygiene is strong; the gaps
  are coverage gaps, not call-style violations.
- The file is very large (7,256 LOC) with many near-duplicate methods.
  Cross-cutting consistency review (matching every `except` to a log
  call) was performed file-wide via grep + chunked reads. There are
  ~120 `except` clauses in real Python (excluding Jython payloads),
  and 14 of them lack any log call.
