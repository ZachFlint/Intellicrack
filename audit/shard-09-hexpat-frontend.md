# Shard 09 — hexpat language pipeline (parsing/lexing)

- **Files audited**: 12
- **Total LOC**: 8083
- **Generated**: 2026-05-22T00:00:00Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 10    |
| MEDIUM   | 33    |
| LOW      | 8     |

- Files missing module-level `_logger`: 0 (legitimate; `__init__.py`, `_pragma.py`, `tokens.py`, `ast_nodes.py` are pure data/re-export modules)
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 10 (across `parser.py`, `stdlib.py`, `interpreter.py`, `hexpat_compiler.py`)

## Findings by file

### src/intellicrack/core/hexpat/__init__.py — LOC 24

**Logger status**: not required (pure re-export)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. Exempt per §4: contains only re-exports.

---

### src/intellicrack/core/hexpat/_pragma.py — LOC 62

**Logger status**: not required (pure dataclass/constants)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. Exempt per §4: pure data — `PragmaInfo` frozen dataclass and module-level constants only, no executable code paths.

---

### src/intellicrack/core/hexpat/tokens.py — LOC 246

**Logger status**: not required (token enum + frozen dataclass + keyword tables only)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. Exempt per §4: only contains `TokenType` enum, `Token` frozen dataclass, and module-level frozenset/dict constants — no methods or operations to log.

---

### src/intellicrack/core/hexpat/ast_nodes.py — LOC 939

**Logger status**: not required (pure AST dataclasses)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. Exempt per §4: every type defined is a `@dataclass(frozen=True)` AST node carrying only fields (`value`, `line`, `column`, `name`, etc.). No methods, no `__init__` overrides, no operations. No `except`/`raise`/`print`/IO anywhere in the file.

---

### src/intellicrack/core/hexpat/errors.py — LOC 160

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L46-53, L87-94, L142-149 — `HexPatError.__init__`, `HexPatParseError.__init__`, and `HexPatRuntimeError.__init__` log at `debug` only. These are the centralised raise-site logs (per §3 #6, raise sites must log). When parse/runtime errors actually occur this is the only log entry, and downstream wrap-and-reraise sites in `stdlib.py` (L1105, L1128, L1929, L1975, L1998, L2021, L2046, L2069, L2091, L2130, L2156) rely on this debug-level entry. Consider promoting at least the parse/runtime error path to `info`/`warning` so error construction is visible at default log levels without losing the deduplication benefit. Marked LOW because behaviour is intentional and consistent, but it does interact with the wrap-and-reraise pattern flagged elsewhere.

---

### src/intellicrack/core/hexpat/lexer.py — LOC 536

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L43-52 — public `tokenize()` performs the entire lex pass with no entry/exit log. The constructor logs init with `source_length` (L37-41), but the actual tokenisation run produces no log line. Fix: add `_logger.debug("hexpat_lex_complete", token_count=len(self._tokens), file_path=self.file_path)` before returning, or an entry log such as `_logger.debug("hexpat_lex_start", file_path=self.file_path)` at the top of `tokenize`. Errors propagate via `HexPatParseError` whose `__init__` logs at debug, so the raise sites at L160, L182, L189, L205, L212, L218, L237, L259, L262, L285, L297, L309, L337, L412, L476, L518 are covered.

---

### src/intellicrack/core/hexpat/interpreter.py — LOC 287

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L94-140 — public `execute()` orchestrates the entire interpreter pipeline (preprocess + lex + parse + evaluate) and reads/produces large amounts of state, but has no entry/exit log. Fix: add `_logger.info("hexpat_execute_start", file_path=file_str, offset=offset)` at top and `_logger.info("hexpat_execute_complete", field_count=len(result))` (after capturing the result) before return.
- [MEDIUM] L142-159 — public `execute_file()` is even more significant: it reads a `.hexpat` file from disk (L158 `pattern_path.read_text(...)`) and then runs the full pipeline. The file-read is an operationally significant read per §2.3 of the criteria (user-provided target). Fix: add `_logger.info("hexpat_execute_file", pattern_path=str(pattern_path), offset=offset)` before the read.
- [MEDIUM] L161-204 — public `execute_bytes()` (testing variant) performs the full pipeline against a raw bytes buffer with no entry/exit log.
- [MEDIUM] L206-229 — public `can_compile_to_json()` runs preprocess + lex + parse just to probe eligibility. L226 `except HexPatError: return False` swallows the exception with no log. Even though by-design probe behaviour, per §3 #2 every `except` block must log. Fix: `_logger.debug("hexpat_compile_to_json_probe_failed", error=str(err))` before `return False`.
- [MEDIUM] L231-260 — public `compile_to_json()` invokes the cross-module `HexPatCompiler` (a bridge into `hexpat_compiler.py`). Per §2.3, bridge invocations must log on both sides. Currently only the `ImportError` path logs (L257). Fix: add an info-level entry log (`_logger.info("hexpat_compile_to_json_start", source_length=len(source))`) before invoking `HexPatCompiler.compile`, and an exit log on success.
- [LOW] L37-41 — module-level constant name `_IMHEX_PATTERNS_DIR` and docstring/path references `ImHex` in identifier text. Project memory forbids the literal string "ImHex" in code/comments (`feedback_no_imhex_name.md`). Not a logging finding but worth surfacing because this audit shard called the rule out explicitly.

---

### src/intellicrack/core/hexpat/type_system.py — LOC 333

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L186-203, L205-217, L219-244, L246-258, L260-268 — `register_struct`, `register_union`, `register_enum`, `register_bitfield`, `register_alias` are state mutations on the type registry (§2.4) but produce no log entry. Logging each individual registration would be very noisy (a typical pattern registers hundreds of types per parse), so this is marked LOW. Consider logging an aggregate count from the caller (`evaluator`) instead of per-call here.
- [LOW] L270-302 — public `resolve()` is the dispatcher for every type lookup and runs in a hot loop. No log appropriate; flagged only to record judgment that it is intentionally silent.

No `except`/`raise`/`print`/IO in file; init log at L164 is correct.

---

### src/intellicrack/core/hexpat/pattern_registry.py — LOC 244

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L200-210 — public `load_source()` reads the full `.hexpat` source from disk via `metadata.file_path.read_text(...)`. This is a user-provided target read per §2.3. No log. Fix: `_logger.debug("pattern_source_load", path=str(metadata.file_path))` before the read.
- [LOW] L142-187 — `match_file()` is well-structured, but the actual match outcome (number of matches found) is not logged. Could add a debug log near the return summarising `matches_count` and the binary size that was probed.

`scan()` (L72-101) is well-logged. `_extract_metadata()` (L213-244) correctly logs read errors via `_logger.exception("pattern_read_error", ...)` at L225.

---

### src/intellicrack/core/hexpat/parser.py — LOC 1652

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L229-234 — `except HexPatParseError as err: self._errors.append(err); self._synchronise(); continue`. The caught exception is collected but no log is emitted at the catch site. Per §3 #2 every `except` block must log. Even though the error is later surfaced via `HexPatAggregateParseError` at L237, the catch itself is silent. Fix: `_logger.debug("hexpat_parse_recover", error=err.message, line=err.line, column=err.column, file_path=self.file_path)` inside the except block. (The constructor on `errors.py` line 46-53 logs at debug but only with `error_type` and `message`, not the recovery context.)
- [HIGH] L237 — `raise HexPatAggregateParseError(tuple(self._errors))`: raise site does not log aggregate error directly. The base `HexPatError.__init__` logs at debug, but a top-level parse failure with multiple collected errors deserves at least an `info` or `warning` log enumerating the count. Fix: `_logger.warning("hexpat_parse_failed", error_count=len(self._errors), file_path=self.file_path)` before raising.
- [HIGH] L774, L989, L1034, L1055 — `except HexPatParseError:` swallowed silently as parser backtracks. These are intentional Pratt/lookahead recovery patterns, but per the STRICT criteria (§3 #2 "any except clause … is a HIGH violation, even if the exception is re-raised") they must log. Backtracks at L774 (sizeof/expression disambiguation), L989 (placement vs expression statement disambiguation), L1034 (top-level placement vs expression statement), L1055 (typed vs untyped const decl). Fix: `_logger.debug("hexpat_parser_backtrack", context="<sizeof|placement|...>", line=..., column=...)` inside each except clause. (The corresponding success case at L840 already logs via `_logger.warning("hexpat_parser_cast_backtrack", ...)` — the four cited sites should follow the same pattern at debug level.)
- [MEDIUM] L203-238 — public `parse()` performs full parsing pass; no entry log and no success-exit log. There is only an error log path (which is itself missing — see above). Fix: `_logger.debug("hexpat_parse_start", file_path=self.file_path, token_count=len(self._tokens))` at entry and `_logger.debug("hexpat_parse_complete", node_count=len(nodes), error_count=len(self._errors))` on success exit.
- [LOW] L840-847 — existing `_logger.warning("hexpat_parser_cast_backtrack", ...)` is logged at `warning` for a successful backtrack into a parenthesised expression. The level is arguably too loud — this is a normal parser fallback (not an anomaly). Suggested level: `debug`. Marked LOW because logging level judgment, not absence.

Many raise sites within the parser (L144, L237, L335, L412, L480, L813, L1515, L1622, etc.) are covered via `HexPatError.__init__` debug logging; not separately flagged.

---

### src/intellicrack/core/hexpat/stdlib.py — LOC 2777

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L1816-1820 (`_time_to_local`) — `except (OverflowError, OSError, ValueError): return PatternValue(value=0)`. Silent swallow returning a zero sentinel. Fix: `_logger.warning("hexpat_time_to_local_failed", epoch=epoch, exc_info=True)` (or `_logger.exception(...)`) before the return.
- [HIGH] L1834-1838 (`_time_to_utc`) — same silent swallow pattern. Fix as above.
- [HIGH] L1863-1869 (`_time_format`) — silent swallow when `time.strftime` fails. Fix: `_logger.warning("hexpat_time_format_failed", format=fmt, exc_info=True)` before `return PatternValue(value="")`.
- [HIGH] L2745-2748 (`_format_string._replace`) — `except (TypeError, ValueError): return str(value)`. Silent fallback on `format(value, format_spec)` failure. Fix: `_logger.debug("hexpat_format_spec_failed", format_spec=format_spec, value_type=type(value).__name__)` before fallback.
- [HIGH] L2750-2753 (`_format_string`) — `except (IndexError, KeyError): return fmt`. Silent swallow of regex substitution failure. Fix: `_logger.warning("hexpat_format_string_failed", fmt=fmt, exc_info=True)` before fallback.
- [MEDIUM] L1101-1105 (`_string_parse_int`) — `except ValueError as exc: ...; raise HexPatRuntimeError(msg) from exc`. Wraps to custom error without explicit log at the raise site; relies on `HexPatError.__init__` debug log. Per §3 #6 this should be logged with traceback. Fix: replace with `_logger.exception("hexpat_string_parse_int_failed", input=s, base=base); raise HexPatRuntimeError(msg) from exc`.
- [MEDIUM] L1124-1128 (`_string_parse_float`) — same pattern. Fix similarly.
- [MEDIUM] L1890-1933 (`_file_open`) — opens a file on the host filesystem at L1926 `path.open(open_mode)` (a §2.3 file mutation / open). No entry log before the open, no success log after. The except clause at L1927 wraps via `HexPatRuntimeError` without local log. Fix: `_logger.info("hexpat_file_open", path=str(path), mode=open_mode)` before the open, `_logger.info("hexpat_file_opened", handle=handle_id, path=str(path))` after success, and `_logger.exception("hexpat_file_open_failed", path=str(path), mode=open_mode)` before re-raising.
- [MEDIUM] L1978-1999 (`_file_write`) — performs a file write (`self._file_handles[handle].write(payload)`). Pattern-driven file write is significant per §2.3. No log before, no log after success; except at L1996 wraps silently. Fix: add info-level entry log noting handle + payload length, and `_logger.exception("hexpat_file_write_failed", handle=handle)` before re-raise.
- [MEDIUM] L1955-1976 (`_file_read`) — reads from file handle; no entry/success log; exception at L1973 silent re-wrap. Per §2.3 user-target reads should log. Fix: add debug entry log + `_logger.exception(...)` at the except.
- [MEDIUM] L2001-2022 (`_file_seek`), L2024-2047 (`_file_size`), L2049-2070 (`_file_resize`), L2072-2092 (`_file_flush`) — same pattern as above; each performs an IO operation and re-wraps OSError to `HexPatRuntimeError` without explicit log at the raise site. Fix each with `_logger.exception(...)` before the `raise`.
- [MEDIUM] L2094-2131 (`_file_remove`) — does log success (L2116 info) and failure (L2124 exception). But the surrounding `fp.close()` failure at L2113-2114 is only a warning and proceeds to unlink. That is reasonable but inconsistent with other sites that abort on OSError. Marked MEDIUM as a consistency note rather than a coverage gap.
- [MEDIUM] L2133-2157 (`_file_create_directories`) — calls `path.mkdir(parents=True, exist_ok=True)` (a §2.3 filesystem mutation). No entry/exit log; except at L2154 wraps OSError silently. Fix: `_logger.info("hexpat_create_directories", path=str(path))` before the mkdir and `_logger.exception(...)` before raising.
- [MEDIUM] L2159-2173 (`_random_set_seed`) — mutates RNG state (significant state mutation per §2.4); no log. Suggest `_logger.debug("hexpat_random_set_seed", seed=...)`.
- [MEDIUM] L2247-2267 (`_env_get`) — reads from `os.environ`; this is user-influenceable config data. Suggest debug-level log noting the variable name (NOT the value, which may be sensitive).
- [LOW] L388-679 (`register_all`) — registers ~150 builtin functions in a single dict literal. After the loop at L676-679 there is no summary log indicating how many builtins were registered. Suggest `_logger.debug("hexpat_builtins_registered", count=len(builtins))` after the loop.
- [LOW] L98-107 (`set_print_sink`) — module-level function mutating shared registry state (significant per §2.4). No log. Suggest debug log noting whether a sink was installed or cleared.
- [LOW] L62-71 (`_create_rng`) docstring at L63 references `ImHex's`; project memory forbids this literal. Not a logging finding but flagged because this shard's instructions called the rule out.
- [LOW] L2733-2739 (`_format_string._replace`) — `except ValueError: _logger.warning(...)`. The log uses `warning` level but this branch is hit for legitimate non-integer field indices (e.g., named fields), which are not really warnings — typical hexpat patterns use `{}` and `{0}` heavily. Suggest demoting to `debug`. Marked LOW.

Initialization log at L237-242 is correct. `_io_print` (L2639), `_io_error` (L2675), `_io_warning` (L2688) all log appropriately. Reflection/no-provider error sites (L2304, L2401, L2409, L2590, L2611) all log before raise.

---

### src/intellicrack/core/hexpat_compiler.py — LOC 823

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L803-806 (`compile_to_dict`) — `except HexPatError as exc: raise HexPatError(exc.message, exc.line, exc.column, exc.file) from exc`. Catches the preprocessor's error, re-wraps as a new `HexPatError` (same type), without logging. Per §3 #2 this is a HIGH violation. Fix: `_logger.exception("hexpat_compile_preprocess_failed", file=exc.file, line=exc.line)` before re-raise.
- [HIGH] L811-814 (`compile_to_dict`) — `except HexPatParseError as exc: raise HexPatError(exc.message, exc.line, exc.column, exc.file) from exc`. Same pattern — catches and re-wraps without logging. Note this also *loses* the `HexPatParseError` subtype (and any `HexPatAggregateParseError` aggregate info) by converting to bare `HexPatError`; that is a separate correctness concern but compounds the logging issue. Fix: `_logger.exception("hexpat_compile_parse_failed", file=exc.file, line=exc.line)` before re-raise.
- [MEDIUM] L764-778 (`compile`) — public static method; no entry/exit log. Delegates to `compile_to_dict`. The exit log at L817 is on `compile_to_dict` only; a top-level compile invocation produces no operational log line at info level. Fix: `_logger.info("hexpat_compile", source_length=len(source))` at entry; subsequent debug log at L817-822 already records success.
- [MEDIUM] L780-823 (`compile_to_dict`) — only an exit `debug` log at L817 (no entry log, no error log path). Combined with the two HIGH findings above, the compile pipeline is essentially silent on failure unless the caller themselves logs. Fix: add `_logger.debug("hexpat_compile_to_dict_start", source_length=len(source))` at L802.
- [LOW] L234-324 (`generate`) — public method. Has a single error log at L257 (`hexpat_generate_no_struct_declaration`). Other raise sites in `generate`'s callees rely on `HexPatError.__init__` debug logging. Acceptable but consider a success log noting field/types count at end.
- [LOW] L670-752 (`_eval_const_expr`) — many raise sites for unsupported expression types, all relying on `HexPatError.__init__` debug logging only. These are user-facing compile errors and might benefit from an aggregated info log from `_gen_field`'s caller, but logging each raise here would be noisy.

---

## Aggregate notes

- **Strong baseline.** All twelve files either have a `module-level _logger` or are exempt per §4 (pure data / re-export). No stdlib `logging` usage, no `print()`, no `contextlib.suppress`, no `# noqa`/`# type: ignore`. The canonical `from intellicrack.core.logging import get_logger` import is used uniformly. Logger name is exactly `_logger` everywhere.
- **Centralised raise-site logging via `errors.py`.** The interpreter pipeline relies on `HexPatError.__init__` (errors.py L46-53), `HexPatParseError.__init__` (L87-94), and `HexPatRuntimeError.__init__` (L142-149) to emit a `debug`-level log every time a custom error is constructed. This satisfies §3 #6 "raise site should log" but at debug level only and with limited context. When wrap-and-reraise occurs (notably `stdlib.py` L1101-1129 and `hexpat_compiler.py` L803-814), the catch site does not add its own log, so the only operational trace is the inner construction's debug line — which is below default visibility.
- **Two distinct silent-except patterns dominate the HIGH findings.**
  1. **Parser backtracking** in `parser.py` L774, L989, L1034, L1055: legitimate Pratt-parser lookahead, but criteria are strict — these need at least `debug` recovery logs. The existing `parser.py` L840 (`hexpat_parser_cast_backtrack` warning) already demonstrates the right shape; the other four sites should adopt the same pattern.
  2. **Time-conversion / format-string fallbacks** in `stdlib.py` L1818, L1836, L1868, L2747, L2752: these silently return a sentinel value (0, "", or the unformatted string). These deserve at least debug logs to make pattern-author bugs (e.g., bad strftime format) traceable.
- **File-IO builtins in stdlib.py lack entry/exit instrumentation.** `_file_open`, `_file_read`, `_file_write`, `_file_seek`, `_file_resize`, `_file_flush`, `_file_create_directories`, `_file_remove` all touch the host filesystem from pattern-language code (a security-sensitive surface). Per §2.3 these should log around the underlying IO call. `_file_remove` is the exception — it does log success and failure. Consistency fix is recommended.
- **Bridge invocation in `interpreter.py` (`compile_to_json` -> `hexpat_compiler.HexPatCompiler`)** is logged only on `ImportError`. Per §2.3 bridge invocations need both intent and outcome logging.
- **Public-method entry/exit logging is the weakest area** across the shard: `HexPatInterpreter.execute*`, `HexPatLexer.tokenize`, `HexPatParser.parse`, `HexPatCompiler.compile*`. These are the public surface of the pipeline; an audit trail at `info` for entry/exit would substantially improve observability of pattern execution without adding noise (these are coarse-grained operations called once per pattern run).
- **Out-of-scope but called out by shard instructions:** `interpreter.py` L39 (`_IMHEX_PATTERNS_DIR`) and `stdlib.py` L63 docstring (`ImHex's`) both contain the literal string "ImHex", which project memory `feedback_no_imhex_name.md` forbids. Recorded as LOW findings even though they are not logging issues, because the shard prompt explicitly highlighted the rule.
- No file in this shard was generated code or otherwise difficult to audit. The largest file (`stdlib.py`, 2777 LOC) is densely packed but its structure is consistent (one `_*` builtin per method), which made auditing tractable.
