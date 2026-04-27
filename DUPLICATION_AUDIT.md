# Intellicrack Duplication Audit

| Field | Value |
|---|---|
| Date | 2026-04-25 (revised after second + third pass verification) |
| Source tree audited | `D:\Intellicrack\src\intellicrack\` (145 Python files, ~141,776 LOC) |
| Verified duplicate groups | 23 |
| Total individual implementations across all groups | 91 |
| Estimated redundant LOC (if all CONSOLIDATE recommendations applied) | ~3,610 |
| Method | Read both/all implementations end-to-end before classifying. Name-based hits without body confirmation were rejected. Second pass resolved every previously-deferred candidate. Third pass added per-group safety notes and audited UI bypass of bridge layer + magic-byte format detection sites. |

Each group below is verified — the function bodies were read and confirmed to operate against the same input/output domain. Per-tool bridges (e.g., `cutter.disassemble` vs `ghidra.disassemble`) are NOT flagged: the user picks the active tool. A *third* native Python implementation that bypasses every connected tool IS flagged.

---

## Group 1 — Win32 constant redeclaration

Same Win32 API constants (PROCESS_VM_*, MEM_*, PAGE_*, TH32CS_SNAP*, INVALID_HANDLE_VALUE, GENERIC_*, OPEN_EXISTING) re-declared as module-level Finals in multiple files instead of imported from the canonical `_win32_types.py`.

| # | path:line | LOC | Backend | Status |
|---|---|---|---|---|
| 1 | `src/intellicrack/bridges/_win32_types.py:21-205` | 185 | Canonical | Authoritative |
| 2 | `src/intellicrack/bridges/x64dbg.py:128-220` (WIN_PROCESS_VM_*, WIN_MEM_*, WIN_PAGE_EXECUTE_READWRITE, TH32CS_SNAP*, PE_HEADER_OFFSET, PE_MAGIC_OFFSET, PE32/64_MACHINE, PE_MACHINE_ARM*, PE_MACHINE_IA64, INVALID_HANDLE_VALUE via _compute_invalid_handle_value, PAGE_NOACCESS/READONLY/READWRITE/EXECUTE/EXECUTE_READ, CMD_LINE_OFFSET_64) | ~70 | Local copies | Duplicate |
| 3 | `src/intellicrack/bridges/named_pipe_client.py:29-32` (`_GENERIC_READ`, `_GENERIC_WRITE`, `_OPEN_EXISTING`, `_INVALID_HANDLE_VALUE`) | 4 | Local copies | Duplicate |
| 4 | `src/intellicrack/sandbox/windows.py:150-152` (`_PIPE_INVALID_HANDLE`, `_PIPE_GENERIC_RW`, `_PIPE_OPEN_EXISTING`) | 3 | Local copies | Duplicate |

**Authoritative pick:** `src/intellicrack/bridges/_win32_types.py` — file's stated purpose is "Pure type definitions and constant values for Win32 API interop … no business logic." It already defines every constant the others redeclare (e.g., `PROCESS_VM_READ=0x0010` at line 29 matches `WIN_PROCESS_VM_READ=0x0010` at x64dbg:129; `INVALID_HANDLE_VALUE=0xFFFFFFFFFFFFFFFF` at line 21 matches both other forms; `IMAGE_FILE_MACHINE_I386=0x014C` at line 135 matches `PE32_MACHINE=0x14C` at x64dbg:141).

**Recommendation:** CONSOLIDATE. Rewrite the local declarations as `from intellicrack.bridges._win32_types import PROCESS_VM_READ as WIN_PROCESS_VM_READ` (or drop the alias entirely and rename usages). Add `GENERIC_READ`, `GENERIC_WRITE`, `OPEN_EXISTING` to `_win32_types.py` since two consumers need them.

**SAFETY (verified second pass):** `_win32_types.INVALID_HANDLE_VALUE` is hard-coded `0xFFFFFFFFFFFFFFFF` (64-bit literal). On 32-bit Python this value never matches what `CreateFileW` returns (`0xFFFFFFFF`), so handle-validity checks would silently break. `bridges/x64dbg.py:188-204` `_compute_invalid_handle_value` does it correctly via `wintypes.HANDLE(-1).value`; `bridges/named_pipe_client.py:32` uses `ctypes.c_void_p(-1).value` which is also correct. **Before consolidating: replace the hard-coded literal in `_win32_types.py:21` with the dynamic computation x64dbg.py uses.** Otherwise the consolidation pushes the 32-bit bug from `sandbox/windows.py` into `named_pipe_client.py` (which is currently correct).

**Risk:** low *after* the INVALID_HANDLE_VALUE fix. **Effort:** S.

---

## Group 2 — PE COFF machine → architecture string

Translate `IMAGE_FILE_MACHINE_*` value to architecture name. Three implementations against the same input domain (PE COFF machine field) producing semantically identical output (arch string).

| # | path:line | LOC | Backend | Status |
|---|---|---|---|---|
| 1 | `src/intellicrack/bridges/process.py:1403-1422` `_machine_to_arch_string` | 20 | Live process (via PE header in mapped image) | Duplicate |
| 2 | `src/intellicrack/bridges/x64dbg.py:147-175` `pe_machine_to_arch` | 29 | Live process (via x64dbg-mapped PE) | Duplicate |
| 3 | `src/intellicrack/bridges/ghidra.py:1707-1798` `_detect_architecture` (PE branch lines 1724-1750) | 27 (PE branch only) | Static file bytes | Duplicate of the PE branch only |

All three map the same set: `0x014C→x86`, `0x8664→x64/x86_64`, `0x01C0/0x01C4→arm`, `0xAA64→arm64`, `0x0200→ia64`. Differences are cosmetic (string `"x64"` vs `"x86_64"`) and which machine values are covered (ghidra also covers MIPS/PPC/RISC-V).

**Authoritative pick:** Extract a new pure helper in `bridges/_win32_types.py` (or a sibling `bridges/_pe_format.py`):

```python
def pe_machine_to_arch(machine: int) -> tuple[str, bool]: ...
```

Returning `(arch_str, is_64bit)` — that's the superset of what the three callers want. ghidra's full coverage (MIPS/PPC/RISC-V) should win because it's the broadest mapping; process.py and x64dbg can normalize the string locally if they prefer `"x64"` over `"x86_64"`.

**Recommendation:** CONSOLIDATE. Add the helper to `_win32_types.py` (or a new `_pe_format.py`); replace the three private methods with delegating calls. ghidra's `_detect_architecture` keeps the multi-format dispatcher (PE/ELF/Mach-O) but the PE branch becomes a one-liner.

**SAFETY (verified second pass):** The PE arch translation actually exists in MORE places than the original three. Second-pass survey found:
- `core/disassembler.py:auto_detect_arch:291-366` — does PE+ELF+Mach-O detection, returns `("x86", "32")`/`("x86", "64")` etc. tuple form (different shape).
- `bridges/process.py:_machine_to_arch_string:1403-1422` — returns `"x64"` (no underscore).
- `bridges/x64dbg.py:pe_machine_to_arch:147-175` — returns `("x64", True)` tuple with bool.
- `bridges/ghidra.py:_detect_architecture:1707-1798` — returns `("x86_64", True)`.
- BridgeCapabilities advertise `["x86", "x86_64"]` strings (`bridges/process.py:939`, `sandbox_bridge.py:104`, `bridges/x64dbg.py:607`).
- `core/orchestrator.py:_ARCH_KEYWORDS:1890-1899` normalizes `AMD64/X86_64 → "x86_64"`, `I386 → "x86"`, `ARM64 → "aarch64"`, `ARM → "arm"`.

Caller string conventions diverge (`"x64"` vs `"x86_64"` vs `("x86","64")` tuple). **Before consolidating: pick one canonical convention** (recommendation: `"x86_64"`/`"x86"`/`"arm64"`/`"arm"` matching ghidra and the orchestrator map). Update process.py callers and any string equality checks. Audit consumers via `rg '== "x64"' src/intellicrack/` before changing.

**Risk:** medium (string convention reconciliation required across at least 5 sites). **Effort:** S–M.

---

## Group 3 — PE format magic constants

Same PE/MZ magic offsets and signatures redeclared per-file.

| # | path:line | Value | Status |
|---|---|---|---|
| 1 | `src/intellicrack/bridges/process.py:227` `_PE_DOS_SIGNATURE = 0x5A4D` | MZ | Local |
| 2 | `src/intellicrack/bridges/process.py:228` `_PE_HEADER_OFFSET_FIELD = 0x3C` | PE pointer offset | Local |
| 3 | `src/intellicrack/bridges/process.py:230` `_PE_SIGNATURE = 0x00004550` | "PE\0\0" int | Local |
| 4 | `src/intellicrack/bridges/x64dbg.py:138` `PE_HEADER_OFFSET = 0x3C` | PE pointer offset | Duplicate of #2 |
| 5 | `src/intellicrack/bridges/x64dbg.py:139` `PE_MAGIC_OFFSET = 0x40` | end of pointer | Local |
| 6 | `src/intellicrack/bridges/x64dbg.py:266` `NT_HEADERS_OPTIONAL_OFFSET = 0x18` | OptionalHeader offset | Local |
| 7 | `src/intellicrack/bridges/ghidra.py:59-62` `_PE_POINTER_OFFSET=0x3C`, `_PE_POINTER_END=0x40`, `_PE_MAGIC=b"PE\x00\x00"`, `_MZ_MAGIC=b"MZ"` | Same values, different rep (bytes vs int) | Duplicate of #1, #2, #3 |
| 8 | `src/intellicrack/bridges/hex_editor.py:234` `_PE32_PLUS_MAGIC = 0x20B` | OptionalHeader magic | Local |

**Authoritative pick:** Add `bridges/_pe_format.py` (sibling to `_win32_types.py`) holding all PE constants in canonical form. `_win32_types.py` already declares the PE *machine* constants — push the magic/offset constants there too or split into a new module.

**Recommendation:** CONSOLIDATE. Risk low; effort S.

---

## Group 4 — Provider `_build_usage_from_completion`

Extracts `prompt_tokens`/`completion_tokens`/`total_tokens` from a non-streaming `ChatCompletion` response.

| # | path:line | LOC | Status |
|---|---|---|---|
| 1 | `src/intellicrack/providers/openai.py:431-452` | 22 | Duplicate |
| 2 | `src/intellicrack/providers/grok.py:455-476` | 22 | Byte-for-byte duplicate of #1 (only docstring text differs) |

Both are `@staticmethod`, same `getattr(..., 0) or 0` pattern, same `total = ... or (prompt + completion)` fallback, same `UsageInfo(...)` construction.

**Authoritative pick:** Lift to `providers/base.py` as a protected method `_build_usage_from_openai_completion`. base.py already hosts other OpenAI-format helpers (`_convert_messages_to_openai_format` at line 596, `_convert_tool_choice_to_openai_format` at line 573).

**Recommendation:** CONSOLIDATE. Move to base; delete from openai.py and grok.py; both providers already inherit from `LLMProviderBase`.

**Risk:** low — pure function, no instance state. **Effort:** S.

---

## Group 5 — Provider `_build_usage_from_chunk_usage`

Same as Group 4 but for streaming-chunk usage objects.

| # | path:line | LOC | Status |
|---|---|---|---|
| 1 | `src/intellicrack/providers/openai.py:454-474` | 21 | Duplicate |
| 2 | `src/intellicrack/providers/grok.py:478-498` | 21 | Byte-for-byte duplicate |

**Authoritative pick:** base.py.

**Recommendation:** CONSOLIDATE. Same fix as Group 4.

**Risk:** low. **Effort:** S.

---

## Group 6 — Provider system-prompt extraction

Concatenate all `role == "system"` messages into a single instruction string.

| # | path:line | LOC | Status |
|---|---|---|---|
| 1 | `src/intellicrack/providers/anthropic.py:717-728` `get_system_prompt` | 12 | Duplicate |
| 2 | `src/intellicrack/providers/google.py:629-642` `_extract_system_instruction` | 14 | Same logic with different name |

Both: `system_parts = [msg.content for msg in messages if msg.role == "system" and msg.content]; return "\n\n".join(system_parts) if system_parts else None`.

**Authoritative pick:** Lift to `providers/base.py` as `_extract_system_messages`.

**Recommendation:** CONSOLIDATE. Risk low; effort S.

---

## Group 7 — Provider tool-call parsing from message

Iterate the OpenAI-shaped `response_message.tool_calls` and convert each into the internal `ToolCall` via the shared `_parse_tool_call_common` helper.

| # | path:line | LOC | Status |
|---|---|---|---|
| 1 | `src/intellicrack/providers/openai.py:476-506` `_parse_openai_tool_calls` | 31 | Duplicate |
| 2 | `src/intellicrack/providers/grok.py:500-531` `_parse_grok_tool_calls` | 32 | Duplicate (only differs in `getattr(tc, "function", None)` defensive check vs explicit `isinstance` typed check) |

Both end up calling `self._parse_tool_call_common(call_id=..., function_name=..., raw_arguments=...)` — that helper is already in base.py.

**Authoritative pick:** Add `_parse_openai_format_tool_calls` to `providers/base.py`. Use `getattr(tc, "function", None)` for compatibility with both the typed OpenAI SDK and Grok's looser response shape.

**Recommendation:** CONSOLIDATE. Risk low; effort S.

---

## Group 8 — Provider HTTP error → typed exception translation

Map `openai.AuthenticationError → AuthenticationError`, `openai.RateLimitError → RateLimitError`, `openai.APIError → ProviderError`, plus `(ConnectionError, TimeoutError, OSError, ValueError) → ProviderError`.

| # | path:line | LOC | Status |
|---|---|---|---|
| 1 | `src/intellicrack/providers/openai.py:418-429` | 12 | Duplicate |
| 2 | `src/intellicrack/providers/grok.py:442-453` | 12 | Same exception classes, same message constants pattern |

**Authoritative pick:** Either a context manager (`@contextmanager def _translate_openai_errors(self, model: str, log_prefix: str): ...`) or a decorator on the provider methods. Lives in base.py since both providers use the official `openai` SDK.

**Recommendation:** CONSOLIDATE via context manager. Risk low; effort S.

---

## Group 9 — Streaming JSON parse-skip

Both providers stream chunks line-by-line and silently skip lines that fail `json.loads` while logging via the same event name `stream_json_parse_skipped`.

| # | path:line | LOC | Status |
|---|---|---|---|
| 1 | `src/intellicrack/providers/openrouter.py:567-592` (decode + warn-and-continue at 590-592) | 26 | Duplicate |
| 2 | `src/intellicrack/providers/ollama.py:1338-1342` | 5 | Same pattern |

The shared piece is small (the try/except itself). The wider streaming loop differs (SSE `data:` framing in openrouter vs JSON-lines in ollama).

**Authoritative pick:** A small helper `_safe_parse_stream_json(line: str, *, logger) -> dict | None` in base.py.

**Recommendation:** CONSOLIDATE the helper only — keep the surrounding stream loops as-is since the framing genuinely differs.

**Risk:** low. **Effort:** S.

---

## Group 10 — Sandbox log-line parsing (largest single duplication)

Both `WindowsSandbox` and `QEMUSandbox` parse the SAME pipe-delimited monitor logs produced by the same in-guest agents (only the file names differ — `file_monitor.log` vs `file_changes.log`, `network_monitor.log` vs `network_activity.log`, etc.). The schemas are identical and produced by the same agent code in `src/intellicrack/sandbox/scripts/`.

11 parser methods are duplicated:

| Operation | Windows | QEMU |
|---|---|---|
| File-change log | `sandbox/windows.py:1454-1480` | `sandbox/qemu.py:2206-2237` |
| Registry-change log | `sandbox/windows.py:1482-1520` | `sandbox/qemu.py:2239-2271` |
| Network-activity log | `sandbox/windows.py:1522-1556` | `sandbox/qemu.py:2322-2373` |
| Process-activity log | `sandbox/windows.py:1558-1592` | `sandbox/qemu.py:2375-2409` |
| Service-change log | `sandbox/windows.py:1594-1617` | `sandbox/qemu.py:2411-2443` |
| Kernel-object log | `sandbox/windows.py:1619-1642` | `sandbox/qemu.py:2445-2477` |
| DLL-load log | `sandbox/windows.py:1644-1667` | `sandbox/qemu.py:2479-2511` |
| Injection log | `sandbox/windows.py:1669-1696` | `sandbox/qemu.py:2513-2546` |
| Resource-sample log | `sandbox/windows.py:1698-1723` | `sandbox/qemu.py:2548-2581` |
| Clipboard log | `sandbox/windows.py:1725-1750` | `sandbox/qemu.py:2583-2616` |
| API-trace log | `sandbox/windows.py:1752-1780` | `sandbox/qemu.py:2618-2651` |

All 22 implementations split lines on `|`, validate field count against a `_*_LOG_MIN_PARTS` constant, build the matching TypedDict (`FileChange`, `RegistryChange`, etc.). The Windows version is more thorough (extracts `old_path`, `size`, `parent_pid`, `exit_code`); the QEMU version discards those and inlines its file I/O. windows.py also has a shared `_read_log_lines(name)` helper at lines 1429-1452 that QEMU re-implements inline in every parser.

**Authoritative pick:** `src/intellicrack/sandbox/windows.py` — its parsers extract more fields per line and use the cleaner `_read_log_lines` abstraction.

**Recommendation:** CONSOLIDATE. Create `src/intellicrack/sandbox/_log_parsers.py` exposing one parser per log type, parameterized by the shared-folder Path and the (configurable) file name. Both `WindowsSandbox.collect_*` and `QEMUSandbox.collect_*` call into the same module. Move `_read_log_lines` into the new module.

**SAFETY (verified second pass):** Schema constants confirmed identical between the two files: `_FILE_LOG_MIN_PARTS = 3`, `_NETWORK_LOG_MIN_PARTS = 10`, `_PROCESS_LOG_MIN_PARTS = 4`, `_SERVICE_LOG_MIN_PARTS = 6` (windows.py:84-88, qemu.py:69-92). qemu.py is MISSING `_REGISTRY_LOG_MIN_PARTS` — at line 2257 it incorrectly uses `_FILE_LOG_MIN_PARTS` (value 3) for the registry-log validation; windows.py defines `_REGISTRY_LOG_MIN_PARTS = 3` separately. Schema-equal-by-coincidence; consolidation will fix this latent bug. Field-index constants have different names (e.g., qemu's `_PROCESS_LOG_NAME_INDEX = 3` vs windows.py extracting `parts[3]` directly) but resolve to the same offsets.

**Risk:** medium — the field-extraction differences (qemu's parsers drop fields the schema supports) need to be reconciled. The full parsing should be done; callers can ignore fields they don't need. **Effort:** M (~600 LOC consolidated to ~300).

---

## Group 11 — Sandbox network-log helpers

Module-level helpers in `sandbox/windows.py`; static-method copies in `sandbox/qemu.py`.

| # | path:line | Function | Status |
|---|---|---|---|
| 1 | `src/intellicrack/sandbox/windows.py:2436-2454` `_split_addr_port` | Module helper | Authoritative |
| 2 | `src/intellicrack/sandbox/qemu.py:2308-2320` `_split_address` | Static method | Duplicate (less robust — windows.py handles `[ipv6]:port`) |
| 3 | `src/intellicrack/sandbox/windows.py:2457-2473` `_coerce_protocol` | Module helper | Authoritative |
| 4 | `src/intellicrack/sandbox/qemu.py:2274-2288` `_coerce_network_protocol` | Static method | Same logic |
| 5 | `src/intellicrack/sandbox/windows.py:2476-2487` `_infer_direction` | Module helper | Authoritative |
| 6 | `src/intellicrack/sandbox/qemu.py:2291-2305` `_coerce_network_direction` | Static method | Same logic |
| 7 | `src/intellicrack/sandbox/windows.py:2490-2508` `_safe_int` | Module helper | Authoritative — no duplicate, but inline `parts[X].isdigit()` reads in qemu.py |
| 8 | `src/intellicrack/sandbox/windows.py:2511-2526` `_safe_float` | Module helper | Authoritative — no duplicate; qemu.py uses inline `int(s) if s.isdigit() else 0` instead |

**Authoritative pick:** `sandbox/windows.py` versions — they're module-level functions (reusable), `_split_addr_port` handles bracketed IPv6, `_safe_int`/`_safe_float` survive non-numeric input that the qemu inline `.isdigit()` checks reject.

**Recommendation:** CONSOLIDATE alongside Group 10 — move into `sandbox/_log_parsers.py` (or a sibling `sandbox/_log_helpers.py`).

**Risk:** low. **Effort:** S.

---

## Group 12 — Sandbox YARA match formatter

Convert a `yara.Match` object to a serializable dict.

| # | path:line | LOC | Status |
|---|---|---|---|
| 1 | `src/intellicrack/sandbox/windows.py:2529-2562` `_format_yara_match` (module function) | 34 | Authoritative — reusable |
| 2 | `src/intellicrack/sandbox/qemu.py:3254-3275` `_format_yara_match` (closure inside `yara_scan`) | 22 | Duplicate, scoped to one method |

Same logic: pull `rule`, `namespace`, `tags`, `strings`, build `formatted` list with `offset`/`identifier`/`data`, return dict with `source` and `scan_type`.

**Authoritative pick:** windows.py's module-level version.

**Recommendation:** CONSOLIDATE. Move to `sandbox/_log_parsers.py` (or a new `sandbox/_yara.py`). Risk low; effort S.

---

## Group 13 — HexPat DSL parser pipeline (largest LOC duplication)

Two completely independent implementations of the same `.hexpat` DSL parser. Neither imports from the other.

| # | path:line | LOC | Coverage | Status |
|---|---|---|---|---|
| 1 | `src/intellicrack/core/hexpat_compiler.py:1-1630` (defines `HexPatError` at 24, `TokenType` enum at 47-114, `Token` dataclass at 117+, `HexPatLexer`, `HexPatParser` at 685, AST nodes, `HexPatCompiler` at 1594) | 1630 | Compiles patterns to a static JSON template (Rust hex editor consumes it). Refuses runtime constructs at line 784 (`_RUNTIME_ONLY_TOKENS`). | Alive |
| 2 | `src/intellicrack/core/hexpat/lexer.py` (536), `parser.py` (1610), `interpreter.py` (237), plus `_pragma.py`, `ast_nodes.py`, `data_reader.py`, `errors.py`, `evaluator.py`, `preprocessor.py`, `tokens.py`, `type_system.py`, `pattern_registry.py`, `stdlib.py` | ~2400 in lexer+parser+interpreter alone | Full evaluator — runs patterns against binary data. | Alive |

`hexpat_compiler.py:230` actually imports the full `HexPatInterpreter` for fallback (so the interpreter calls into the compiler in one direction and the compiler is referenced in another). Both stacks tokenize, parse, and AST-build the same source language.

The two parsers parse the same DSL grammar (struct/union/enum/bitfield with the same operators). The compiler's parser refuses `if`/`while`/`for`/`match` and runtime constructs (line 784); the interpreter's parser supports them. The shared subset (struct/union/enum/bitfield/type-spec/expression parsing) is duplicated.

**Authoritative pick:** `core/hexpat/` — modular, has separate AST, type system, and evaluator; supports the full language. The compiler's role (emitting a static JSON template) is legitimate, but it should reuse the lexer + AST and emit JSON from the *shared* AST instead of re-parsing.

**Recommendation:** CONSOLIDATE. Refactor `hexpat_compiler.py` so it:
1. Imports `HexPatLexer`, `HexPatParser`, AST nodes from `core/hexpat/`.
2. Walks the shared AST and rejects runtime nodes at code-gen time (instead of refusing tokens at parse time).
3. Reduces to a thin AST→JSON visitor (~300 LOC instead of 1630).

This deletes ~1300 LOC and removes a second source of truth for the DSL grammar. The two parsers WILL drift over time if left as-is (already happening — interpreter supports newer constructs).

**SAFETY (verified second pass):** AST node shapes are INCOMPATIBLE. `core/hexpat/ast_nodes.py` nodes are `@dataclass(frozen=True)` and carry `line: int`/`column: int` on every node (required by the evaluator's error reporting). `core/hexpat_compiler.py:209-432` nodes are `@dataclass` (mutable) and lack line/column entirely. Consolidation requires the compiler to consume the richer (frozen + line/column) shared nodes — adding line/column is fine because the compiler can ignore them. The reverse (dropping line/column from shared) would BREAK the interpreter's error messages. Additionally, the compiler refuses runtime constructs at PARSE TIME (`hexpat_compiler.py:784` `_RUNTIME_ONLY_TOKENS`); the shared parser accepts them. The refactor must move the runtime-construct rejection into an AST-WALK rejection inside the compiler. JSON-output behavioral tests must continue to pass.

**Risk:** medium — shared AST node shapes need to match the compiler's JSON emit assumptions. Existing behavior tests for compile output must continue to pass. **Effort:** L.

---

## Group 14 — UI hex-dump formatter

Format `bytes` as a 16-byte-per-line hex+ASCII dump with addresses.

| # | path:line | LOC | Status |
|---|---|---|---|
| 1 | `src/intellicrack/ui/panels/frida_panel.py:1813-1830` `_format_hex_dump(data, base_address)` | 18 | Duplicate |
| 2 | `src/intellicrack/ui/panels/x64dbg_panel.py:2594-2612` `_format_hex_dump(address, data)` | 19 | Duplicate (parameter order swapped, output prefix differs: `08X  ` vs `0x08X  `) |

Same algorithm: 16-byte chunks, `b:02X` hex, ASCII printable filter, `chr(b) if low <= b < high else "."`.

**Authoritative pick:** Move to a new `src/intellicrack/ui/_hex_format.py` (or `core/_hex_format.py` for cross-layer use) with signature `format_hex_dump(data: bytes, base_address: int, *, address_prefix: str = "") -> str`.

**Recommendation:** CONSOLIDATE. The hex_editor widget code in `ui/panels/hex_editor_widget.py` does much richer rendering and should NOT be replaced — it's a different domain (live QPainter rendering, not text formatting for a console). Risk low; effort S.

---

## Group 15 — Hex-editor mixin QThread workers

Each hex_editor mixin defines a custom `QThread` subclass that wraps a single synchronous PyO3 hexcore call and emits a `*_finished`/`*_error` signal pair. The pattern is replicated 8 times. A canonical `BridgeCallWorker` already exists in `ui/panels/async_bridge.py:115-156` for *coroutines*; these workers wrap *synchronous* PyO3 calls so they cannot use it directly, but the pattern is otherwise identical.

| # | path:line | Worker | Status |
|---|---|---|---|
| 1 | `src/intellicrack/ui/panels/async_bridge.py:115-156` `BridgeCallWorker` | Coroutine variant | Authoritative for coroutines |
| 2 | `src/intellicrack/ui/panels/hex_editor/_search.py:55-134` `SearchWorker` | Sync PyO3 wrapper | Duplicate pattern |
| 3 | `src/intellicrack/ui/panels/hex_editor/_search.py:136-270` `NumericSearchWorker` | Sync PyO3 wrapper | Duplicate pattern |
| 4 | `src/intellicrack/ui/panels/hex_editor/_comparison.py:35-87` `DiffWorker` | run_bridge_coroutine wrapper | Duplicate pattern |
| 5 | `src/intellicrack/ui/panels/hex_editor/_statistics.py:64+` `StatisticsWorker` | Sync PyO3 wrapper | Duplicate pattern |
| 6 | `src/intellicrack/ui/panels/hex_editor/_sandbox.py:84+` `SandboxWorker` | Bridge call wrapper | Duplicate pattern |
| 7 | `src/intellicrack/ui/panels/hex_editor/_signatures.py:38+` `SignatureScanWorker` | Sync PyO3 wrapper | Duplicate pattern |
| 8 | `src/intellicrack/ui/panels/hex_editor/_scripting.py:933+` `ScriptWorker` | Script exec wrapper | Duplicate pattern |
| 9 | `src/intellicrack/ui/panels/hex_editor/_sections.py:58+` `StringsExtractionWorker` | Sync PyO3 wrapper | Duplicate pattern |

Each: stores constructor args as instance attributes, runs the wrapped operation in `run()`, emits one of two signals on success/failure, and connects `finished → deleteLater`. The sole differences are which method gets called and the signal type.

**Authoritative pick:** Add `GenericCallableWorker(callable, args, kwargs)` to `ui/panels/async_bridge.py` (sibling of `BridgeCallWorker`). Mixins instantiate it inline:

```python
worker = GenericCallableWorker(self._document.search_hex, query, max_results)
worker.call_finished.connect(self._on_search_finished)
worker.call_error.connect(self._on_search_error)
worker.start()
```

**Recommendation:** CONSOLIDATE. Replace 8 worker classes with one. **Risk:** low. **Effort:** M.

**SAFETY (verified second pass):** Several workers are NOT thin callable wrappers — they own private compute methods that compose the result:
- `StatisticsWorker._compute` (`_statistics.py:107-133`) calls `_compute_entropy_map`, `_compute_byte_distribution`, `_compute_type_distribution`, `_compute_classification` on itself.
- `NumericSearchWorker._search_native`/`_search_fallback` (`_search.py:209-270`) — the fallback does its own chunked iteration with struct.unpack and alignment checks.

For these workers the consolidation requires extracting `_compute`/`_search_*` into module-level free functions taking `(document, params)`, then `GenericCallableWorker(free_function, args)` becomes the wrapper. The truly thin workers (`DiffWorker`, `ScriptWorker`, `SignatureScanWorker`, `StringsExtractionWorker`) collapse cleanly. Realistic LOC saved is ~150 (not ~250) after extracting embedded compute logic.

---

## Group 16 — UI inline `QMessageBox` usage

`ui/confirmation_dialog.py` provides `ToolConfirmationDialog` (centralized) but generic `QMessageBox.warning/critical/information` calls are scattered across 11+ files for similar error-display flows.

| # | Files (representative) |
|---|---|
| 1 | `src/intellicrack/ui/panels/hex_editor/panel.py:622-665` (file load/save errors) |
| 2 | `src/intellicrack/ui/panels/hex_editor/_yara.py` (YARA errors) |
| 3 | `src/intellicrack/ui/panels/hex_editor/_disassembly.py` |
| 4 | `src/intellicrack/ui/panels/hex_editor/_patches.py` |
| 5 | `src/intellicrack/ui/panels/hex_editor/_hashing.py` |
| 6 | `src/intellicrack/ui/panels/hxd_panel.py` |
| 7 | `src/intellicrack/ui/provider_config.py` |
| 8 | `src/intellicrack/ui/sandbox_config.py` |
| 9 | `src/intellicrack/ui/tool_config.py` |

Each call follows `QMessageBox.warning(self, title, message)` / `.critical(...)` / `.information(...)` — same constructor pattern, no shared theming, no shared default parent.

**Recommendation:** CONSOLIDATE LIGHT — add `ui/_dialogs.py` exposing `show_error(parent, title, message, *, exc=None)`, `show_warning(...)`, `show_info(...)` that wrap `QMessageBox` and add consistent logging. NOT a "delete all calls" mandate — only adopt where the call sites already log the same message.

**Risk:** low. **Effort:** S–M depending on adoption breadth.

---

## Group 17 — `hex_editor_panel.py` re-export shim

`hex_editor_panel.py` is a 15-line backward-compat re-export.

| # | path:line | LOC | Status |
|---|---|---|---|
| 1 | `src/intellicrack/ui/panels/hex_editor_panel.py:1-15` (re-exports from `hex_editor/`) | 15 | Stub forwarder |
| 2 | `src/intellicrack/ui/panels/hex_editor/panel.py:1-1321` `HexEditorPanel` | 1321 | Authoritative |
| 3 | `src/intellicrack/ui/panels/hex_editor_widget.py:1-2217` `HexEditorWidget` | 2217 | Distinct (low-level QPainter widget used *by* HexEditorPanel) |
| 4 | `src/intellicrack/ui/panels/hxd_panel.py:1-353` `HxDPanel` | 353 | Distinct (HxD.exe embed, orthogonal) |

Only #1 is a duplicate (forwarder). #2, #3, #4 are layered: `panel.py` contains the panel + mixins; `hex_editor_widget.py` is the QPainter rendering surface used inside it; `hxd_panel.py` embeds an external HxD process.

**Recommendation:** KEEP ALL — but document at the top of each file what they are, since the names are confusingly similar.

**SAFETY (verified second pass):** The shim IS imported by `src/intellicrack/ui/panels/__init__.py:18` (`from intellicrack.ui.panels.hex_editor_panel import HexEditorPanel`). DELETION requires also updating that import to `from intellicrack.ui.panels.hex_editor import HexEditorPanel`. `pyproject.toml:437` has a per-file ruff ignore configured for the shim path — that line would also need to be removed if the shim is deleted. KEEP option is risk-free.

**Risk:** low. **Effort:** XS.

---

## Group 18 — Bridge/registry tool-dispatch

Tool-call dispatch happens in two places, but verification confirms they layer rather than duplicate.

| # | path:line | Role |
|---|---|---|
| 1 | `src/intellicrack/core/tools.py:443-554` `ToolRegistry.execute_tool_call` | Tool dispatch: name → bridge → method invocation |
| 2 | `src/intellicrack/core/orchestrator.py:1127-1242` `Orchestrator._execute_tool_calls` | Orchestrator wraps with confirmation + ToolResult timing, then *delegates* to (1) |

**Recommendation:** KEEP ALL — orchestrator is a thin layer over the registry, not a re-implementation. Distinction: orchestrator owns confirmation/cancellation/audit; registry owns method routing. Document the layering with a one-line module docstring on each.

**Risk:** none — flagging in case future readers re-flag this. **Effort:** XS.

---

## Group 19 — Subprocess / logging / capstone / theme / layering (NOT duplicates)

Verified clean — listed so future audits don't re-flag them. Second-pass additions noted.

| # | Concern | Location | Status |
|---|---|---|---|
| 1 | subprocess wrapper | `src/intellicrack/core/_subprocess.py:14-85` | Single canonical import point — no duplication |
| 2 | logging setup | `src/intellicrack/core/logging.py:302-406` | Single setup; everywhere else uses `get_logger(__name__)` |
| 3 | capstone disassembly | `src/intellicrack/core/disassembler.py:90-300` | Single Cs() init for the in-app inline disassembly path |
| 4 | theme/font/icon managers | `src/intellicrack/ui/resources/{theme,font,icon}_manager.py` | Singleton each, properly factored |
| 5 | Win32 struct definitions | `src/intellicrack/bridges/_win32_types.py:246-467` (PROCESSENTRY32, MODULEENTRY32, THREADENTRY32, MEMORY_BASIC_INFORMATION) | Single source — bridges import correctly |
| 6 | Tool-bridge polymorphism | All `*Bridge.disassemble`, `*.read_memory`, etc. | Per-backend by design — user picks active tool |
| 7 | `_convert_messages_to_openai_format` | `src/intellicrack/providers/base.py:597-660` | Already centralized; openai/grok/ollama/openrouter/huggingface delegate correctly |
| 8 | `ToolCallBufferManager` | `src/intellicrack/providers/base.py:663+` | Already centralized; all OpenAI-format streaming providers reuse it |
| 9 | `_convert_tool_choice_to_openai_format` | `src/intellicrack/providers/base.py:573-594` | Already centralized |
| 10 | `bridges/sandbox_bridge.py` ↔ `sandbox/manager.py` | `bridges/sandbox_bridge.py:718-803` (`create`/`destroy`) delegates to `sandbox/manager.py:148-267`; `bridges/sandbox_bridge.py:1622-1759` (analysis methods) delegates to `sandbox/analysis.py` (e.g., `extract_iocs` at 429, `generate_timeline` at 523, `match_behaviors` at 900, `diff_reports` at 1256) | Verified pure delegation. Bridge adds: input validation (line 747 `_VALID_SANDBOX_TYPES` check), primitive→`SandboxConfig` marshaling (lines 753-757), `SandboxError → ToolError` translation, dict serialization for the LLM tool surface. No logic duplicated. |
| 11 | `core/orchestrator.py` ↔ `core/analysis_aggregator.py` | `orchestrator.py:30` imports `AnalysisAggregator`, instantiates and uses it at `orchestrator.py:1441-1442` (`_run_bridge_analysis`). `analysis_aggregator.py:34-201` owns the bridge-collection + dedup logic; orchestrator.py owns the conversation loop and session attachment. | Verified clean layering. Aggregator (236 LOC) is single-purpose; orchestrator (2110 LOC) calls it once per binary load. |
| 12 | Provider model-capability heuristics (`_is_chat_model`, `_infer_context_window`, `_infer_supports_vision`) | `providers/openai.py:167-225`, `providers/grok.py:169-232` | Verified: only present in 2 providers. Anthropic, Google, OpenRouter, Ollama, HuggingFace do NOT use prefix-based heuristics (they consult their SDK's typed model list or query a discovery endpoint). The pattern is shared but the data (which prefixes count) is provider-specific. With only 2 occurrences and provider-specific tables, lifting to a strategy class costs roughly what it saves. |

**Recommendation:** KEEP ALL — no action. Items 10–12 were previously in "Needs human judgment" and are now confirmed clean.

---

## Group 20 — Native PE struct parsing across bridges (verified second pass)

Three sites natively parse PE structures in Python (going around any external tool). Originally listed under "Needs human judgment". Second-pass reading of every `struct.unpack_from` call confirmed the duplication.

| # | path:line | Function | Backend | Read mechanism |
|---|---|---|---|---|
| 1 | `src/intellicrack/bridges/x64dbg.py:4031-4058` `_parse_section_entry` | Section header parse | Live process memory | `await self.read_memory()` (x64dbg pipe) |
| 2 | `src/intellicrack/bridges/x64dbg.py:4060-4087` `get_module_sections` | Section iteration | Live process memory | x64dbg pipe |
| 3 | `src/intellicrack/bridges/x64dbg.py:4089-4129, 4172-4208` `_read_export_tables` / `_build_export_entries` | Export-table walk | Live process memory | x64dbg pipe |
| 4 | `src/intellicrack/bridges/x64dbg.py:4240-4294` `get_entry_point` | Entry-point RVA | Live process memory | x64dbg pipe |
| 5 | `src/intellicrack/bridges/x64dbg.py:5470-5508` `get_tls_callbacks` | TLS callback array | Live process memory | x64dbg pipe |
| 6 | `src/intellicrack/bridges/x64dbg.py:5528-5564` `get_resources` | Resource directory | Live process memory | x64dbg pipe |
| 7 | `src/intellicrack/bridges/hex_editor.py:4499-4544` `_detect_pe_va_mappings` | DOS+COFF+OptionalHeader walk for VA mapping | HexDocument bytes | `self._read_doc_bytes()` (sync PyO3) |
| 8 | `src/intellicrack/bridges/hex_editor.py:4546-4570` `_parse_pe_sections_va` | Section iteration for VA mapping | HexDocument bytes | `self._read_doc_bytes()` |
| 9 | `src/intellicrack/ui/panels/hex_editor/_templates.py:313-417` `_bookmark_pe_structure` / `_bookmark_pe_sections` | Bookmark-emitting walk for UI annotation | HexDocument bytes | `self.document.read()` (uses `int.from_bytes`, not `struct.unpack`) |

The byte-read mechanism legitimately differs (async pipe / sync PyO3 / sync PyO3 with `int.from_bytes`). The struct interpretation is identical. Confirmed shared low-level operations:

| Operation | Re-implemented at |
|---|---|
| `e_lfanew` from DOS header (offset 0x3C) | x64dbg.py:4021, hex_editor.py:4509, _templates.py:335 |
| COFF `NumberOfSections` (offset 6) | x64dbg.py:4074, hex_editor.py:4514, _templates.py:373-385 |
| COFF `SizeOfOptionalHeader` (offset 20) | x64dbg.py:4075, hex_editor.py:4515, _templates.py:356-368 |
| COFF `Machine` field (offset 4) → `pe_machine_to_arch` | x64dbg.py:4102, 5483, 5541 (also covered by Group 2) |
| Section header unpack at offsets 8/12/16/20/36 | x64dbg.py:4044-4047, hex_editor.py:4563-4566 |
| Data Directory entry offset by `is_pe64` | x64dbg.py:4104, 5485, 5543 (3× in same file) |
| Data Directory entry RVA+Size at `(offset, offset+4)` | x64dbg.py:4110/4112, 5489/5490, 5547/5548 (3× in same file) |
| Optional Header `ImageBase` PE32 vs PE32+ branch | hex_editor.py:4519-4521 |

x64dbg.py alone re-extracts the COFF Machine field three times (lines 4102, 5483, 5541), recomputes the Data Directory base offset three times (4104, 5485, 5543), and unpacks the Data Directory entry header three times (4110-4118, 5489-5490, 5547-5548).

**Authoritative pick:** A new `src/intellicrack/bridges/_pe_format.py` module (sibling of `_win32_types.py`) exposing pure-byte helpers with no I/O:

```python
def read_dos_e_lfanew(data: bytes) -> int: ...
def unpack_coff_header(data: bytes, offset: int) -> tuple[int, int, int, int]:  # (machine, num_sections, opt_hdr_size, characteristics)
def get_pe_bitness(data: bytes, coff_offset: int) -> tuple[str, bool]:  # arch, is_pe64
def get_data_directory_offset(coff_offset: int, *, is_pe64: bool, entry_index: int) -> int
def read_data_directory_entry(data: bytes, offset: int) -> tuple[int, int]:  # (rva, size)
def unpack_section_header(data: bytes, offset: int) -> dict[str, int | str]
def iterate_section_headers(data: bytes, sections_offset: int, count: int) -> Iterator[dict]
def rva_to_file_offset(sections: list[dict], rva: int) -> int | None
def unpack_optional_header_image_base(data: bytes, offset: int, *, is_pe64: bool) -> int
```

Each call site keeps its own I/O wrapper (async `await self.read_memory(...)` for x64dbg; `self._read_doc_bytes(...)` for hex_editor.py; `self.document.read(...)` for _templates.py) but feeds the resulting `bytes` into the shared helpers.

**Recommendation:** CONSOLIDATE. Rough LOC accounting:
- x64dbg.py: 6 functions doing PE parsing → reduce inline parsing by ~80 LOC after delegation.
- hex_editor.py: 2 functions → reduce by ~30 LOC.
- _templates.py: stays mostly the same since it uses `int.from_bytes` for bookmark generation (color metadata is the bulk); maybe ~10 LOC saved by replacing the offset-arithmetic helpers.

Total: ~120 LOC eliminated; one canonical PE-format helper that future bridges can reuse.

**Risk:** medium — x64dbg.py's parsing is bound to async memory reads, so the helpers must remain pure (bytes in, dict/tuple out). The behavioral surface (which PE features are extracted) must not change. Existing x64dbg integration tests against real PE binaries must continue to pass. **Effort:** M.

---

## Group 21 — Provider HTTP-status → typed-exception block

The same `if status_code in {HTTP_UNAUTHORIZED, HTTP_FORBIDDEN}: raise AuthenticationError; if status_code == HTTP_RATE_LIMITED: raise RateLimitError; if status_code == HTTP_SERVICE_UNAVAILABLE: raise ProviderError(_ERR_MODEL_LOADING ...)` block is repeated inline 5 times in huggingface.py and once (extracted as `_raise_stream_http_error`) in openrouter.py. Originally listed under "Needs human judgment"; second-pass reading confirms the same 3-line decision tree at every site.

| # | path:line | Form |
|---|---|---|
| 1 | `src/intellicrack/providers/openrouter.py:393-415` `_raise_stream_http_error` (static method) | Already extracted — authoritative within openrouter |
| 2 | `src/intellicrack/providers/openrouter.py:140-146` (inline in `connect`) | Inline duplicate within same file |
| 3 | `src/intellicrack/providers/openrouter.py:352-357` (inline in `chat`) | Inline duplicate within same file |
| 4 | `src/intellicrack/providers/huggingface.py:236-240` (in `connect`) | Inline duplicate |
| 5 | `src/intellicrack/providers/huggingface.py:361-365` (in `list_models` or similar) | Inline duplicate |
| 6 | `src/intellicrack/providers/huggingface.py:566-571` (in `chat`) | Inline duplicate |
| 7 | `src/intellicrack/providers/huggingface.py:719-725` (in `chat_stream`) | Inline duplicate |
| 8 | `src/intellicrack/providers/huggingface.py:800-805` (in another stream method) | Inline duplicate |

Each of the 7 inline blocks is 3-5 lines and uses the same `HTTP_UNAUTHORIZED`, `HTTP_FORBIDDEN`, `HTTP_RATE_LIMITED`, `HTTP_SERVICE_UNAVAILABLE` constants. The error-message-template constants (`_ERR_CREDENTIAL_INVALID`, `_ERR_RATE_LIMITED`, `_ERR_MODEL_LOADING`, `_ERR_API_ERROR`) differ between providers, so a shared helper must be parameterized over messages.

**Authoritative pick:** Add to `providers/base.py`:

```python
@dataclass(frozen=True, slots=True)
class HttpErrorMessages:
    auth_invalid: str
    rate_limited: str
    service_unavailable: str
    api_error: str

@staticmethod
def _raise_typed_for_status(
    status_code: int,
    exc: Exception,
    *,
    messages: HttpErrorMessages,
    extract_503_message: Callable[[Exception], str] | None = None,
) -> None: ...
```

Each provider passes its own `HttpErrorMessages` instance plus an optional `extract_503_message` callback (huggingface uses one to dig the model-loading message out of the response body).

**Recommendation:** CONSOLIDATE. Lift to base.py; replace 7 inline blocks (≈ 30 LOC) with single-line calls. openrouter's existing static method can be deleted in favor of the base helper.

**Risk:** low — pure exception-raising helper, no state. Each provider keeps its own message constants. **Effort:** S.

---

## Group 22 — UI bypass of bridge layer for tool-provided functionality

The hex editor UI panels invoke native Python implementations (`HexDisassembler`, `YaraScanner`, `pefile`) DIRECTLY instead of routing through the hex_editor bridge — even though the bridge already exposes those exact operations. Net result: the bridge layer is bypassed, the orchestrator/AI cannot intercept the operation, and the same logic is exercised through two paths.

| # | UI bypass site | Bridge equivalent (already exists) | Native implementation |
|---|---|---|---|
| 1 | `ui/panels/hex_editor/_disassembly.py:169` `disassembler = HexDisassembler_cls()` (unconditional in `_on_disassemble`) | `bridges/hex_editor.py:2922-2990` `disassemble(offset, count, arch, mode)` — already wraps `HexDisassembler` internally | `core/disassembler.py:106-258` `HexDisassembler` (capstone wrapper) |
| 2 | `ui/panels/hex_editor/_yara.py:138` `scanner = YaraScanner_cls()` (unconditional in `_on_yara_scan`) | `bridges/hex_editor.py:2992-3034` `yara_scan(rule_source)` and `:3036-3070` `yara_scan_files(rule_paths)` | `core/yara_scanner.py:74-302` `YaraScanner` |
| 3 | `ui/panels/hex_editor/_sections.py:143-173` `_populate_sections` opens the file with `pefile.PE(...)` directly | `bridges/hex_editor.py:4499-4570` `_detect_pe_va_mappings` / `_parse_pe_sections_va` — same parse via struct.unpack | `pefile` (third-party) |
| 4 | `ui/panels/hex_editor/_sections.py:175-207` `_populate_imports` opens the file with `pefile.PE(...)` directly | Cutter `get_imports` (`bridges/cutter.py:1575-1583`), Ghidra `get_imports` (`bridges/ghidra.py:2517-2559`) | `pefile` |
| 5 | `ui/panels/hex_editor/_sections.py:209-243` `_populate_exports` opens the file with `pefile.PE(...)` directly | Cutter `get_exports` (`bridges/cutter.py:1585-1593`), Ghidra `get_exports` (`bridges/ghidra.py:2561-2602`) | `pefile` |

Sites 1–2: the hex editor is the user's primary work surface. Routing through `bridges/hex_editor.disassemble`/`yara_scan` (which themselves use the native implementations) keeps the orchestrator/AI in the loop and gives every disassembly/YARA invocation a single audit point. The native classes (`HexDisassembler`, `YaraScanner`) themselves are NOT duplications — they are the bridge's chosen implementation. The duplication is the UI calling them around the bridge.

Sites 3–5: the hex editor's "Sections / Imports / Exports" tabs show data about the file the user has open. The hex_editor bridge already extracts PE sections natively; the UI should call that bridge method instead of opening the file with `pefile` separately. When a static-analysis tool (Cutter or Ghidra) is connected and has the same file loaded, the bridge layer can opportunistically delegate to it for richer data — today there's no path to do that because the UI hardcodes `pefile`.

**Authoritative pick:**
- For 1, 2: the existing `bridges/hex_editor` methods (`disassemble`, `yara_scan`, `yara_scan_files`).
- For 3–5: extend `bridges/hex_editor.py` with `get_pe_sections()`/`get_pe_imports()`/`get_pe_exports()` methods that read from the open `HexDocument` and return shape-stable dicts. Internally these can use `pefile` OR the existing native struct.unpack code at `bridges/hex_editor.py:4499-4570` — the public surface is what matters.

**Recommendation:** REFACTOR the UI to invoke the bridge instead of native classes/libraries. Concrete steps:
1. `_disassembly.py:_on_disassemble` — replace `HexDisassembler_cls()` instantiation with `run_bridge_coroutine_async(self.bridge.disassemble(offset, count, arch, mode), on_success=..., on_error=...)`.
2. `_yara.py:_on_yara_scan` — same pattern, calling `self.bridge.yara_scan(rule_source)` (or `yara_scan_files`).
3. `_sections.py:_populate_*` — add bridge methods (`get_pe_sections`, `get_pe_imports`, `get_pe_exports`) then route through them. Eliminates the direct `pefile` import from the UI.

**Risk:** medium — the bridge methods are async and the UI calls are currently synchronous. Each refactor needs `run_bridge_coroutine_async` (already in `ui/panels/async_bridge.py:194`) with `on_success`/`on_error` callbacks to keep the Qt main thread responsive. Existing UI behavior must remain unchanged for the user. **Effort:** M (~250 LOC touched across 3 UI files; bridge methods 3–5 need to be added). **LOC saved:** ~150 from removing UI-side native invocations and pefile parsing.

---

## Group 23 — Magic-byte file-format detection (5+ sites)

Detecting `MZ`/`PE\0\0`/`\x7fELF`/Mach-O magics from raw bytes is implemented natively in five+ places. This expands the original Group 2 to include format-detection (not just arch translation).

| # | path:line | Operation |
|---|---|---|
| 1 | `core/disassembler.py:auto_detect_arch:291-366` | Detects PE/ELF/Mach-O magic, parses machine field, returns `(arch_str, mode_str)` |
| 2 | `bridges/ghidra.py:_detect_format:1689-1705` | Detects PE/ELF/Mach-O magic, returns format name |
| 3 | `bridges/ghidra.py:_detect_architecture:1707-1798` | Detects PE/ELF/Mach-O magic, parses machine, returns `(arch_str, is_64bit)` |
| 4 | `bridges/process.py:_detect_arch_via_pe_header:1424-1503` | Reads PE from live process, detects PE magic via DOS header |
| 5 | `bridges/x64dbg.py:_read_pe_header:4001-4028` | Reads PE from live process, validates `MZ` and `PE\x00\x00` |
| 6 | `ui/panels/hex_editor/_sections.py:_auto_detect_file_type:335-382` | Detects PE/ELF/Mach-O/ZIP magic, picks a UI template |

Sites 4–5 read from live process memory — different domain from sites 1, 2, 3, 6 (which read from file or hex-document bytes). But the magic-comparison logic itself is the same.

**Authoritative pick:** `bridges/_pe_format.py` (the new module proposed in Group 20) should also expose:

```python
def detect_format(data: bytes) -> Literal["pe", "elf", "macho", "zip", "raw"]
def detect_format_and_arch(data: bytes) -> tuple[str, str, bool]  # (format, arch, is_64bit)
```

Sites 1–3 and 6 collapse into delegating one-liners. Sites 4–5 (live process memory) still need their own async-read prelude, then call `detect_format(buffer)` on the bytes they fetched.

**Recommendation:** CONSOLIDATE alongside Group 20. **Risk:** low — the operation is byte-pattern comparison; output domains are well-defined. The arch-string normalization (Group 2 safety note) applies here too — pick one convention. **Effort:** S after Group 20's `_pe_format.py` exists. **LOC saved:** ~60 across the 6 sites.

---

# Consolidation roadmap (ordered by value over effort)

| Order | Group | Action | LOC saved (est.) | Effort | Risk |
|---|---|---|---|---|---|
| 1 | 4, 5, 6, 8 (provider OpenAI-format helpers) | Lift `_build_usage_from_completion`, `_build_usage_from_chunk_usage`, system-message extractor, HTTP error-translation context manager into `providers/base.py`. Delete from openai.py + grok.py + anthropic.py + google.py. | ~120 | S | low |
| 2 | 21 (provider HTTP-status → typed-exception helper) | Add `_raise_typed_for_status(status_code, exc, *, messages: HttpErrorMessages, extract_503_message=None)` to `providers/base.py`. Replace 7 inline blocks in openrouter.py and huggingface.py. | ~30 | S | low |
| 3 | 7 (provider tool-call parsing) | Add `_parse_openai_format_tool_calls` to base; delete from openai.py/grok.py. | ~60 | S | low |
| 4 | 14 (UI hex-dump formatter) | New `ui/_hex_format.py` with one `format_hex_dump`. | ~30 | S | low |
| 5 | 9 (streaming JSON helper) | Add `_safe_parse_stream_json` helper to base. | ~25 | S | low |
| 6 | 1, 3 (Win32 + PE constants) | Move `GENERIC_*`, `OPEN_EXISTING`, PE magic/offsets into `_win32_types.py` (or sibling `_pe_format.py`). Replace local declarations with imports. | ~80 | S | low |
| 7 | 2 (PE machine→arch) | Add `pe_machine_to_arch` to `_win32_types.py`/`_pe_format.py`. Replace 3 implementations. | ~70 | S | low |
| 8 | 11, 12 (sandbox helpers + YARA formatter) | New `sandbox/_log_helpers.py` with split-addr / coerce / safe_int / safe_float / yara formatter. Both sandboxes import. | ~120 | S | low |
| 9 | 15 (hex_editor QThread workers) | `GenericCallableWorker` in `async_bridge.py`. Replace 8 workers with inline instantiations. | ~250 | M | low |
| 10 | 20 (native PE struct parsing) | New `bridges/_pe_format.py` with pure-byte helpers (DOS/COFF/section-header unpack, data-directory walk, RVA→file-offset). Each call site keeps its own I/O wrapper but delegates struct interpretation. | ~120 | M | medium |
| 11 | 10 (sandbox log parsers) | New `sandbox/_log_parsers.py` with one parser per log type. Both backends call it. | ~600 | M | medium |
| 12 | 13 (HexPat parser unification) | Rewrite `hexpat_compiler.py` to use shared `core/hexpat/` lexer + AST; reduce to JSON-emit visitor. | ~1300 | L | medium |
| 13 | 17 (hex_editor_panel.py shim) | Either delete (if unused) or add 1-line module docstring clarifying it forwards. | 15 (if delete) | XS | low |
| 14 | 16 (UI dialog helpers) | Optional: `ui/_dialogs.py`. Adopt opportunistically. | ~50 | S | low |
| 15 | 23 (magic-byte format detection) | Add `detect_format`/`detect_format_and_arch` to `bridges/_pe_format.py`. Replace 6 sites. | ~60 | S | low |
| 16 | 22 (UI bypass of bridge layer) | Refactor `_disassembly.py:169`, `_yara.py:138`, `_sections.py:143-243` to call `bridges/hex_editor` methods via `run_bridge_coroutine_async`. Add `get_pe_sections`/`get_pe_imports`/`get_pe_exports` to the bridge. | ~150 | M | medium |

**Total estimated reduction at full adoption:** ~3,610 LOC.

---

# Statistics summary

| Category | Verified groups | Implementations | Estimated LOC saved |
|---|---|---|---|
| Win32 / PE constants | 2 (Groups 1, 3) | 12 | ~80 |
| PE arch translation | 1 (Group 2) | 3 | ~70 |
| Provider OpenAI-format helpers | 5 (Groups 4–9) | 11 | ~230 |
| Provider HTTP-status mapping | 1 (Group 21) | 8 | ~30 |
| Sandbox parsing & helpers | 3 (Groups 10–12) | 26 | ~750 |
| HexPat DSL pipeline | 1 (Group 13) | 2 (entire stacks) | ~1,300 |
| UI hex-dump formatter | 1 (Group 14) | 2 | ~30 |
| UI QThread worker pattern | 1 (Group 15) | 9 | ~250 |
| UI dialogs (optional) | 1 (Group 16) | 11 | ~50 |
| UI panel forwarders | 1 (Group 17) | 1 stub | 15 |
| Native PE struct parsing | 1 (Group 20) | 9 | ~120 |
| UI bypass of bridge layer | 1 (Group 22) | 5 | ~150 |
| Magic-byte format detection | 1 (Group 23) | 6 | ~60 |
| Layered (KEEP ALL) | 2 (Groups 18, 19) | 12 noted | 0 |
| **TOTAL (all CONSOLIDATE applied)** | **20 actionable** | **~91** | **~3,610** |

---

# Needs human judgment — RESOLVED in second-pass review

All six previously-deferred candidates were re-read in full during the second pass. Resolutions:

1. **`bridges/sandbox_bridge.py` ↔ `sandbox/manager.py`** → **RESOLVED: KEEP ALL.** Verified by reading `sandbox_bridge.py:718-803` (`create`, `destroy`) and `sandbox/manager.py:148-267`. The bridge does input validation (`_VALID_SANDBOX_TYPES` check at `sandbox_bridge.py:747`), primitive→`SandboxConfig` marshaling (lines 753-757), `SandboxError → ToolError` translation, and dict serialization. No lifecycle or parser logic is duplicated. Analysis methods (`extract_iocs` etc., `sandbox_bridge.py:1622-1759`) delegate to `sandbox/analysis.py` (`extract_iocs:429`, `generate_timeline:523`, `match_behaviors:900`, `diff_reports:1256`). Documented in Group 19 row 10.

2. **Native PE parsing across `bridges/x64dbg.py`, `bridges/hex_editor.py`, `ui/panels/hex_editor/_templates.py`** → **RESOLVED: PROMOTE TO Group 20 (CONSOLIDATE).** Verified every `struct.unpack_from` call. Confirmed redundant operations: e_lfanew extraction (3×), COFF NumberOfSections (3×), COFF SizeOfOptionalHeader (3×), COFF Machine (3× in x64dbg.py alone), section-header unpack (2×), data-directory offset calculation (3× in x64dbg.py). New module `bridges/_pe_format.py` recommended. ~120 LOC saved.

3. **Provider model-capability heuristics (`_is_chat_model`, `_infer_context_window`, `_infer_supports_vision`)** → **RESOLVED: KEEP AS-IS.** Verified that only `providers/openai.py:167-225` and `providers/grok.py:169-232` define these methods. Anthropic, Google, OpenRouter, Ollama, HuggingFace use SDK-typed model lists or discovery endpoints instead. With only 2 occurrences and provider-specific data tables (the heuristic is what differs, not the surrounding code), lifting to a strategy class costs roughly what it saves. Documented in Group 19 row 12. Re-evaluate if a third provider adopts prefix-based capability inference.

4. **`bridges/hex_editor.py:4514-4620` PE section-mapping vs `bridges/x64dbg.py:5470-5600` PE TLS/resource parsing** → **RESOLVED: SUBSUMED BY Group 20.** These are two of the nine sites listed in Group 20's table; their shared interpretation (DOS/COFF/section walk) is consolidated into `_pe_format.py` while each call site keeps its own I/O wrapper.

5. **`providers/openrouter.py:393-415` `_raise_stream_http_error`** → **RESOLVED: PROMOTE TO Group 21 (CONSOLIDATE).** Second-pass `rg` revealed huggingface.py has the same 3-5 line HTTP-status → typed-exception block inline at 5 different sites (lines 236-240, 361-365, 566-571, 719-725, 800-805) plus 2 inline copies in openrouter.py (140-146, 352-357). Total 8 implementations of the same decision tree. Helper added to base.py with parameterized `HttpErrorMessages`. ~30 LOC saved.

6. **`core/orchestrator.py` ↔ `core/analysis_aggregator.py`** → **RESOLVED: KEEP ALL.** Verified by reading `orchestrator.py:1430-1448` (`_run_bridge_analysis`) and `analysis_aggregator.py:1-100`. orchestrator.py imports AnalysisAggregator at line 30 and instantiates it at line 1441. Aggregator (236 LOC) owns bridge-collection + dedup; orchestrator (2110 LOC) calls it once per binary load and attaches the result to the session. No logic duplicated. Documented in Group 19 row 11.

**Outcome of second pass:** 4 items moved into verified groups (sandbox_bridge → Group 19; PE parsing → new Group 20; OpenRouter helper → new Group 21; orchestrator/aggregator → Group 19). 2 items confirmed clean and documented in Group 19 (sandbox_bridge layering, model heuristics). Zero candidates remain pending.
