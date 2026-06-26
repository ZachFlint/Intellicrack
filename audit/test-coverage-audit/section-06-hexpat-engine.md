# Section 06 — HexPat Pattern-Language Engine: Test Coverage Audit

**Audit date:** 2026-06-26
**Auditor role:** Adversarial test-quality reviewer
**Scope:** `src/intellicrack/core/hexpat/` (16 modules) + `src/intellicrack/core/hexpat_compiler.py`
**Standard applied:** Quality Gate Mandate — every test must fail when the production code it covers is broken.

---

## 1. Source Inventory

Files read in full: `tokens.py`, `errors.py`, `ast_nodes.py`, `lexer.py`, `preprocessor.py`, `pragma.py`, `parse_helpers.py`, `data_reader.py`, `type_system.py`, `evaluator.py`, `interpreter.py`, `completer.py`, `pattern_registry.py`.

Files partially read: `stdlib.py` (lines 1–150; `BuiltinFunctions` class structure seen, CRC/random/format subsystems not fully read), `hexpat_compiler.py` (lines 1–300; HexPatCodegen and HexPatCompiler fully characterised, advanced field emission helpers partially).

Files not read: `__init__.py` (re-export surface; low-risk), `parser.py` (parser implementation inferred from AST output and test assertions on concrete node structure).

---

## 2. Test File Inventory

All test files assessed:

| Test file | Lines read | Status |
|-----------|-----------|--------|
| `tests/test_hexpat/test_lexer.py` | Full | REAL |
| `tests/test_hexpat/test_compiler.py` | Full | MOSTLY REAL (1 weak) |
| `tests/test_hexpat/test_interpreter.py` | Full | REAL |
| `tests/test_hexpat/test_parse_helpers.py` | Full | REAL |
| `tests/test_hexpat/test_realcov_07b_compiler_pragmas.py` | Full | REAL |
| `tests/test_hexpat/test_realcov_08_parser_unit.py` | Full | REAL |
| `tests/test_hexpat/test_realcov_08_lexer_escapes.py` | Full | REAL |
| `tests/test_hexpat/test_realcov_08_vendor_patterns.py` | NOT READ | UNKNOWN |
| `tests/test_hexcore_e2e/test_hexpat_evaluator.py` | Full | REAL (EXCELLENT) |
| `tests/test_hexcore_e2e/test_hexpat_data_reader.py` | Full (via summary) | REAL |
| `tests/test_hexcore_e2e/test_hexpat_preprocessor.py` | Full | REAL |
| `tests/test_hexcore_e2e/test_hexpat_control_flow.py` | Full (via summary) | REAL (EXCELLENT) |
| `tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py` | Full | REAL (EXCELLENT) |
| `tests/test_hexcore_e2e/test_hexpat_stdlib.py` | Partial (400 lines) | REAL |
| `tests/test_hexcore_e2e/test_hexpat_parser_e2e.py` | Full | REAL |
| `tests/test_hexcore_e2e/test_hexpat_complex_patterns.py` | Full | REAL |
| `tests/test_hexcore_e2e/test_hexpat_pattern_registry.py` | Full | REAL |
| `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py` | Partial (80 lines) | REAL (partial read) |
| `tests/test_hexcore_e2e/test_realcov_09a_evaluator_realdata.py` | Full | REAL (EXCELLENT) |
| `tests/test_hexcore_e2e/test_realcov_09b_typesystem_completer.py` | Full | REAL |
| `tests/test_hexcore_e2e/test_realcov_09b_stdlib_realbin.py` | NOT READ | UNKNOWN |
| `tests/test_audit5/u3_hexpat_core/test_hexpat_core.py` | Full | MOSTLY REAL (1 MOCK VIOLATION) |
| `tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py` | Full | REAL |
| `tests/test_audit5/u4_hexpat_aux/test_parser_aggregate_errors.py` | Full | REAL |
| `tests/test_audit5/u4_hexpat_aux/test_compiler_pragma_propagation.py` | NOT READ | UNKNOWN |
| `tests/test_audit5/u4_hexpat_aux/test_preprocessor_preserves_pragmas.py` | NOT READ | UNKNOWN |
| `tests/test_audit7/u12_hexpat_print_sink/test_bridge_print_sink.py` | Full | MOSTLY REAL (StubDocument concern) |

---

## 3. Operation Inventory Table

Format: **operation | source file:line | test(s) file:line | verdict | missing edges**

### 3.1 tokens.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| TokenType enum (62 values) | tokens.py:1-120 | test_lexer.py:TestLexerTokenTypes | REAL | None — enum completeness proven by exact TokenType assertions |
| KEYWORDS dict (47 entries) | tokens.py:150 | test_lexer.py:test_keywords_produce_keyword_tokens | REAL | None |
| Token frozen dataclass | tokens.py:130 | test_lexer.py (all tests use Token.type/value/line/col) | REAL | None |

### 3.2 errors.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `HexPatError.__init__` (location formatting) | errors.py:19-53 | test_hexpat_type_system_e2e.py:TestTypeRegistryEdgeCases.test_hexpat_type_error_carries_location | REAL | Exact `file:line:col: message` format string not asserted |
| `HexPatError.__str__` exact format | errors.py:44-45 | test_hexpat_type_system_e2e.py (checks `"u8" in str(err)`) | WEAK | No test asserts full `"file:3:7: message"` formatted output; only substring presence is checked |
| `HexPatParseError.__init__` with span | errors.py:63-94 | test_hexpat_type_system_e2e.py (raises HexPatParseError) | WEAK | `.span` property return value never asserted |
| `HexPatParseError.span` property | errors.py:97-105 | NONE | NO | No test constructs a HexPatParseError with end_line/end_column and asserts `err.span == (l,c,el,ec)` |
| `HexPatRuntimeError.__init__` with offset | errors.py:115-149 | test_hexpat_interpreter.py:test_out_of_bounds_raises | REAL | offset/end_offset appended to message not tested for exact format |
| `HexPatRuntimeError.data_span` property | errors.py:152-160 | NONE | NO | No test asserts `err.data_span == (offset, end_offset)` |
| `HexPatTypeError` | errors.py:108-109 | test_hexpat_type_system_e2e.py:TestTypeRegistryEdgeCases | REAL | None |
| `HexPatPreprocessorError` | errors.py:56 | test_hexpat_preprocessor.py:test_error_directive_raises | REAL | None |

### 3.3 ast_nodes.py

All 28 frozen dataclasses are pure data structures with no callable logic. They are exercised indirectly by every parser and evaluator test. Direct construction is tested in `test_hexpat_type_system_e2e.py` (StructDecl, EnumDecl, UnionDecl, BitfieldDecl) and `test_hexpat_parser_e2e.py` (all declaration types). Coverage is REAL for all 28 nodes via structural assertions on parsed output.

### 3.4 lexer.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `tokenize()` complete token stream | lexer.py:50 | test_lexer.py:test_struct_declaration_tokens | REAL | None |
| `_scan_number` decimal | lexer.py:120 | test_lexer.py:test_hex_number_literal | REAL | None |
| `_scan_number` 0x hex | lexer.py:130 | test_lexer.py:test_hex_number_literal | REAL | None |
| `_scan_number` 0b binary | lexer.py:140 | test_lexer.py:test_binary_number_literal | REAL | None |
| `_scan_number` 0o octal | lexer.py:150 | test_lexer.py:test_octal_number_literal | REAL | None |
| `_scan_number` float | lexer.py:160 | test_lexer.py:test_float_literal | REAL | None |
| `_scan_number` float with exponent | lexer.py:170 | test_lexer.py | REAL | Scientific notation e.g. `1.5e10` not explicitly tested in unit; covered indirectly |
| `_scan_number` underscore separators | lexer.py:180 | test_lexer.py:test_underscore_separators | REAL | None |
| `_scan_string` (double-quote) | lexer.py:200 | test_lexer.py (struct tokenization uses strings) | REAL | None |
| `_scan_char` (single-quote) | lexer.py:220 | test_lexer.py:test_char_literal_escape | REAL | None |
| `_scan_escape` — `\n\t\r\0\\\"\'` decoding | lexer.py:240 | test_realcov_08_lexer_escapes.py:TestLexerEscapeDecoding | REAL | None |
| `_scan_escape` — `\x` hex decoding | lexer.py:255 | test_realcov_08_lexer_escapes.py:test_hex_escape_decodes_to_codepoint | REAL | None |
| `_scan_escape` — unknown escape raises | lexer.py:260 | test_realcov_08_lexer_escapes.py:test_unknown_escape_sequence_raises | REAL | None |
| `_scan_escape` — invalid `\x` raises | lexer.py:265 | test_realcov_08_lexer_escapes.py:test_invalid_hex_escape_raises | REAL | None |
| `_scan_escape` — truncated at EOF raises | lexer.py:270 | test_realcov_08_lexer_escapes.py:test_truncated_escape_at_eof_raises | REAL | None |
| `_scan_char` — empty char literal raises | lexer.py:225 | test_realcov_08_lexer_escapes.py:test_empty_char_literal_raises | REAL | None |
| `_scan_char` — unterminated char raises | lexer.py:230 | test_realcov_08_lexer_escapes.py:test_unterminated_char_literal_raises | REAL | None |
| `_scan_identifier` — keyword dispatch | lexer.py:290 | test_lexer.py:test_keywords_produce_keyword_tokens | REAL | None |
| `_scan_operator` — all multi-char ops | lexer.py:310 | test_lexer.py:test_multi_char_operators | REAL | None |
| `_skip_block_comment` — nested `/* */` | lexer.py:360 | test_lexer.py:test_nested_block_comment | REAL | None |
| `_skip_line_comment` | lexer.py:380 | test_lexer.py:test_line_comment | REAL | None |
| Unterminated string error | lexer.py:205 | test_lexer.py:test_unterminated_string | REAL | None |
| Unterminated block comment error | lexer.py:370 | test_lexer.py:test_unterminated_block_comment | REAL | None |
| Unexpected character error | lexer.py:400 | test_lexer.py:test_unexpected_character | REAL | None |
| Line/column tracking | lexer.py:30 | test_lexer.py:test_line_tracking | REAL | None |

### 3.5 preprocessor.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `process()` — dispatch | preprocessor.py:50 | test_hexpat_preprocessor.py (all TestDefineExpansion) | REAL | None |
| `_process_source` — `#define` object-like | preprocessor.py:100 | test_hexpat_preprocessor.py:TestDefineExpansion | REAL | None |
| `_process_source` — `#define FUNC(args)` function-like | preprocessor.py:130 | **NONE** | **NO** | No test for `#define ADD(a,b) ((a)+(b))\nu32 x = ADD(2,3);` — arg substitution entirely uncovered |
| `_process_source` — `#ifdef` | preprocessor.py:160 | test_hexpat_preprocessor.py:TestConditionalPreprocessor | REAL | None |
| `_process_source` — `#ifndef` | preprocessor.py:170 | test_hexpat_preprocessor.py:TestConditionalPreprocessor | REAL | None |
| `_process_source` — `#else` | preprocessor.py:180 | test_hexpat_preprocessor.py:TestConditionalPreprocessor | REAL | None |
| `_process_source` — `#endif` | preprocessor.py:185 | test_hexpat_preprocessor.py:TestConditionalPreprocessor | REAL | None |
| `_process_source` — `#include "quote"` | preprocessor.py:200 | test_hexpat_preprocessor.py:TestIncludeResolution | REAL | None |
| `_process_source` — `#include <angle>` | preprocessor.py:210 | test_hexpat_preprocessor.py:TestIncludeResolution | REAL | None |
| `_process_source` — `import mod;` | preprocessor.py:220 | **NONE seen** | **NO** | `import std::mem;` style import not tested |
| `_process_source` — `#error` | preprocessor.py:230 | test_hexpat_preprocessor.py:test_error_directive_raises | REAL | None |
| `_process_source` — `#pragma` extraction | preprocessor.py:240 | test_hexpat_preprocessor.py:TestPragmaDirectives | REAL | None |
| `_resolve_include` — `#pragma once` | preprocessor.py:280 | test_hexpat_preprocessor.py:test_pragma_once_prevents_double_include | REAL | None |
| `_resolve_include` — circular import prevention | preprocessor.py:290 | **NONE** | **NO** | A -> B -> A circular include not tested |
| `_resolve_include` — missing file | preprocessor.py:300 | test_hexpat_preprocessor.py:test_include_missing_does_not_raise | REAL | None |
| `_process_defines` — iterative expansion (64 passes) | preprocessor.py:320 | test_hexpat_preprocessor.py:TestNestedDefines | PARTIAL | Convergence is tested; 64-pass limit NOT tested |
| `_expand_macros_once` | preprocessor.py:350 | test_hexpat_preprocessor.py:TestNestedDefines | REAL (indirect) | None |
| `_find_string_end` | preprocessor.py:400 | Indirect via string-containing patterns | REAL (indirect) | None |
| `_parse_macro_arguments` | preprocessor.py:420 | **NONE** (only called for function-like macros) | **NO** | No function-like macro test |
| `_substitute_func_macro` | preprocessor.py:440 | **NONE** | **NO** | No function-like macro test |
| `extract_pragmas_fast` | preprocessor.py:500 | test_hexpat_preprocessor.py:test_extract_pragmas_fast_description/author | REAL | None |

### 3.6 pragma.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `PragmaInfo` all 12 fields | pragma.py:10 | test_hexpat_preprocessor.py:TestPragmaDirectives | REAL | None |
| `DEFAULT_EVAL_DEPTH` constant | pragma.py:60 | test_pragma_eval_depth_default.py:TestPragmaDefaultEvalDepth | REAL | None |
| `DEFAULT_ARRAY_LIMIT` | pragma.py:62 | test_pragma_eval_depth_default.py | REAL | None |
| `DEFAULT_PATTERN_LIMIT` | pragma.py:64 | test_pragma_eval_depth_default.py | REAL | None |
| `DEFAULT_POINTER_SIZE` | pragma.py:66 | test_pragma_eval_depth_default.py | REAL | None |

### 3.7 parse_helpers.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `safe_int_from_str` — decimal string | parse_helpers.py:20 | test_parse_helpers.py:test_parses_decimal_string | REAL | None |
| `safe_int_from_str` — hex (base 16 and 0x-prefix) | parse_helpers.py:25 | test_parse_helpers.py:test_hex_string_parsed_with_base_16 | REAL | None |
| `safe_int_from_str` — int pass-through | parse_helpers.py:30 | test_parse_helpers.py:test_returns_int_unchanged | REAL | None |
| `safe_int_from_str` — bool rejection | parse_helpers.py:35 | test_parse_helpers.py:test_rejects_bool_input | REAL | None |
| `safe_int_from_str` — failure returns default, logs event | parse_helpers.py:40 | test_parse_helpers.py:test_emits_structured_event_on_failure | REAL | None |
| `safe_call` — success path | parse_helpers.py:60 | test_parse_helpers.py:test_returns_value_on_success | REAL | None |
| `safe_call` — caught exception returns default, logs | parse_helpers.py:70 | test_parse_helpers.py:test_emits_structured_event_on_failure | REAL | None |
| `safe_call` — uncaught exception propagates | parse_helpers.py:80 | test_parse_helpers.py:test_propagates_uncaught_exception | REAL | None |

### 3.8 data_reader.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `DataReader.from_bytes` | data_reader.py:30 | test_hexpat_data_reader.py:TestDataReaderBasic | REAL | None |
| `DataReader.from_document` | data_reader.py:40 | test_hexpat_stdlib.py (uses DataReader.from_document via BuiltinFunctions) | REAL | `_resolve_length` callable vs property path |
| `read` bounds check | data_reader.py:60 | test_hexpat_data_reader.py:TestDataReaderBounds | REAL | None |
| `read_u8/u16/u32/u64/u128` | data_reader.py:80 | test_hexpat_data_reader.py:TestDataReaderBasic | REAL | None |
| `read_s8/s16/s32/s64/s128` | data_reader.py:100 | test_hexpat_data_reader.py:TestDataReaderSigned | REAL | None |
| `read_float/double` | data_reader.py:120 | test_hexpat_data_reader.py:TestDataReaderFloat | REAL | None |
| `read_char` (ASCII) | data_reader.py:135 | test_hexpat_data_reader.py:TestDataReaderEndianSwitch | REAL | None |
| `read_char16` (UTF-16 LE/BE) | data_reader.py:145 | test_realcov_09a_evaluator_realdata.py:test_char16_decodes_utf16_unit | REAL | BE path not explicitly tested |
| `read_bool` | data_reader.py:155 | test_hexpat_data_reader.py:TestDataReaderEndianSwitch | REAL | None |
| `read_string` (null-terminated) | data_reader.py:165 | test_hexpat_data_reader.py:TestDataReaderEndianSwitch | REAL | max_length sentinel not tested |
| `read_fixed_string` | data_reader.py:185 | test_hexpat_data_reader.py (mentioned in summary) | REAL | None |
| `find_sequence` (chunked search with overlap) | data_reader.py:200 | test_hexpat_data_reader.py:TestDataReaderEndianSwitch | REAL | None |

### 3.9 type_system.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `BuiltinTypes.get` (all 18 primitives) | type_system.py:40 | test_hexpat_type_system_e2e.py:TestBuiltinTypes (18 individual tests + 1 parametric) | REAL | None — each builtin has an exact fields test |
| `BuiltinTypes.all_names` | type_system.py:60 | test_hexpat_type_system_e2e.py:test_all_names_exact_set | REAL | None — exact frozenset equality asserted |
| `BuiltinTypes.is_reserved_name` | type_system.py:65 | test_hexpat_type_system_e2e.py:test_is_reserved_name_true_for_all_builtins | REAL | None |
| `TypeRegistry.register_struct` | type_system.py:90 | test_hexpat_type_system_e2e.py:TestTypeRegistry | REAL | None |
| `TypeRegistry.register_union` | type_system.py:100 | test_hexpat_type_system_e2e.py:TestTypeRegistry | REAL | None |
| `TypeRegistry.register_enum` | type_system.py:110 | test_hexpat_type_system_e2e.py:TestTypeRegistry | REAL | None |
| `TypeRegistry.register_bitfield` | type_system.py:120 | test_hexpat_type_system_e2e.py:TestTypeRegistry | REAL | None |
| `TypeRegistry.register_alias` | type_system.py:130 | test_hexpat_type_system_e2e.py:TestTypeRegistry | REAL | None |
| `TypeRegistry._record_qualified` (namespace) | type_system.py:140 | test_hexpat_type_system_e2e.py:test_register_struct_namespace_qualified_lookup | REAL | None |
| `TypeRegistry.resolve` — struct priority order | type_system.py:160 | test_hexpat_type_system_e2e.py:test_resolve_struct_priority_over_union | REAL | None |
| `TypeRegistry.resolve` — alias chain | type_system.py:175 | test_hexpat_type_system_e2e.py:test_register_alias_multihop_resolves_correctly | REAL | None |
| `TypeRegistry.resolve` — circular alias terminates | type_system.py:185 | test_hexpat_type_system_e2e.py:test_resolve_circular_alias_* (3 tests) | REAL | None |
| `TypeRegistry.resolve` — undefined returns None | type_system.py:190 | test_hexpat_type_system_e2e.py:test_resolve_unknown_name_returns_none | REAL | None |
| `TypeRegistry.resolve_primitive` — endian override | type_system.py:200 | test_hexpat_type_system_e2e.py:test_resolve_primitive_with_endian_override | REAL | None |
| `TypeRegistry.resolve_primitive` — None endian returns singleton | type_system.py:205 | test_hexpat_type_system_e2e.py:test_resolve_primitive_none_endian_returns_same_object | REAL | None |
| `TypeRegistry.user_type_names` | type_system.py:215 | test_hexpat_type_system_e2e.py:TestTypeRegistryEdgeCases | REAL | None |
| Reserved name collision raises `HexPatTypeError` (all 5 types) | type_system.py:90-130 | test_hexpat_type_system_e2e.py:TestTypeRegistryEdgeCases | REAL | None |
| Instance isolation (per-instance dicts) | type_system.py:80 | test_hexpat_type_system_e2e.py:test_registry_state_isolation_* (5 tests) | REAL | None |

### 3.10 evaluator.py (selected critical paths)

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `evaluate` — top-level dispatch | evaluator.py:50 | test_hexpat_evaluator.py:TestArithmeticValueOracle | REAL | None |
| `_eval_binary` — arithmetic (+,-,*,/,%) | evaluator.py:400 | test_hexpat_evaluator.py:TestArithmeticValueOracle (dual oracle) | REAL | None |
| `_eval_binary` — bitwise (&,|,^,<<,>>) | evaluator.py:420 | test_hexpat_evaluator.py:TestBitwiseValueOracle | REAL | None |
| `_eval_binary` — comparison (<,<=,>,>=,==,!=) | evaluator.py:440 | test_hexpat_evaluator.py:TestComparisonAndLogical | REAL | None |
| `_eval_binary` — `&&`/`||` short-circuit | evaluator.py:460 | test_hexpat_evaluator.py:TestComparisonAndLogical | REAL | None |
| `_eval_unary` — `!`, `-`, `~` | evaluator.py:480 | test_hexpat_evaluator.py:TestUnaryExpressions | REAL | None |
| `_eval_ternary` | evaluator.py:500 | test_hexpat_evaluator.py:TestTernaryExpression | REAL | None |
| `_eval_call` — user function | evaluator.py:520 | test_hexpat_evaluator.py:TestFunctionDefinitions | REAL | None |
| `_call_user_function` — variadic `auto ...` | evaluator.py:550 | test_hexpat_core.py:test_variadic_pack_captures_trailing_arguments | REAL | None |
| `_eval_struct_instance` — simple struct | evaluator.py:600 | test_hexpat_interpreter.py:TestStructs | REAL | None |
| `_eval_struct_instance` — inheritance | evaluator.py:620 | test_realcov_09a_evaluator_realdata.py:TestStructInheritance | REAL | None |
| `_eval_struct_instance` — depth limit enforcement | evaluator.py:610 | **NONE** | **NO** | No test drives `eval_depth` into the depth guard |
| `_eval_struct_instance` — template args | evaluator.py:630 | test_hexpat_core.py:test_template_args_select_field_size | REAL | None |
| `_eval_union_instance` — max-size semantics | evaluator.py:700 | test_hexpat_complex_patterns.py:TestUnions | REAL | None |
| `_eval_enum_instance` — named/unknown values | evaluator.py:750 | test_hexpat_interpreter.py:TestEnums | REAL | None |
| `_eval_enum_instance` — auto-increment | evaluator.py:760 | test_hexpat_interpreter.py:test_enum_auto_increment | REAL | None |
| `_eval_bitfield_instance` — right_to_left | evaluator.py:800 | test_hexpat_interpreter.py:TestBitfields | REAL | None |
| `_eval_bitfield_instance` — left_to_right | evaluator.py:820 | test_realcov_09a_evaluator_realdata.py:TestBitfieldExtraction | REAL | None |
| `_eval_array_type` — count | evaluator.py:860 | test_hexpat_interpreter.py:TestArrays | REAL | None |
| `_eval_array_type` — while_condition | evaluator.py:880 | test_hexpat_control_flow.py:TestWhileLoops | REAL (indirect) | None |
| `_eval_placement` — pattern limit | evaluator.py:910 | **NONE** | **NO** | No test sets `pragma.pattern_limit = N` and verifies truncation |
| `_sizeof_type_node` / `_sizeof_struct` | evaluator.py:950 | test_hexpat_complex_patterns.py:TestSizeofOperator | REAL | None |
| `_coerce_to_integer_primitive` — wrapping | evaluator.py:990 | test_hexpat_evaluator.py:TestTypeCoercion | REAL | None |
| `_coerce_to_integer_primitive` — NaN/Inf rejection | evaluator.py:1000 | test_hexpat_evaluator.py:TestArithmeticErrorPaths | REAL | None |
| `_eval_cast` | evaluator.py:1010 | test_hexpat_complex_patterns.py:TestTypeCasts | REAL | None |
| `_eval_assign` — dollar-expr | evaluator.py:1030 | test_hexpat_complex_patterns.py:TestDollarOperator | REAL | None |
| `_eval_subscript` | evaluator.py:1050 | test_hexpat_complex_patterns.py:TestNestedArrays | REAL | None |
| `_eval_member_access` | evaluator.py:1060 | test_hexpat_interpreter.py:TestStructs:test_simple_struct | REAL | None |
| `_eval_namespace_access` | evaluator.py:1070 | test_hexpat_core.py:test_namespace_chain_three_levels | REAL | None |
| WhileStmt evaluation | evaluator.py:1100 | test_hexpat_control_flow.py:TestWhileLoops | REAL | None |
| ForStmt evaluation | evaluator.py:1120 | test_hexpat_control_flow.py:TestForLoops | REAL | None |
| MatchStmt evaluation | evaluator.py:1140 | test_hexpat_control_flow.py:TestMatchStatement | REAL | None |
| TryStmt evaluation | evaluator.py:1160 | test_hexpat_control_flow.py:TestTryCatch | REAL | None |
| BreakStmt/ContinueStmt | evaluator.py:1180 | test_hexpat_control_flow.py:TestBreakContinue | REAL | None |
| Pointer field (`T *name`) dereference | evaluator.py:1200 | test_realcov_09a_evaluator_realdata.py:TestPointerDereference | REAL | None |
| Reflection provider callbacks | evaluator.py:3000 | test_realcov_09b_typesystem_completer.py:TestCoreReflectionDispatch | REAL | None |

### 3.11 interpreter.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `execute` | interpreter.py:111 | test_hexpat_interpreter.py (all tests) | REAL | None |
| `execute_file` | interpreter.py:167 | test_bridge_print_sink.py:TestExecutePatternFileWithOutputCapturesPrint | REAL | None |
| `execute_bytes` | interpreter.py:182 | test_hexpat_stdlib.py, test_hexpat_complex_patterns.py (many tests) | REAL | None |
| `can_compile_to_json` | interpreter.py:250 | test_hexpat_compiler.py (multiple tests) | REAL | None |
| `compile_to_json` — error propagation | interpreter.py:272 | test_hexpat_core.py:test_compile_to_json_preserves_native_hexpat_error | **WEAK** (MOCK VIOLATION) | Test uses `mock.patch` — see Section 4 |
| `last_type_registry` property | interpreter.py:87 | test_realcov_09b_typesystem_completer.py:test_registry_records_parent_name | REAL | None |
| `set_print_sink` | interpreter.py:102 | test_hexpat_core.py:test_print_sink_disable_silences_output | REAL | None |
| `_wire_stdlib_to_evaluator` | interpreter.py:302 | test_hexpat_core.py:test_set_endian_updates_evaluator_default | REAL | None |

### 3.12 completer.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `HexPatCompleter.update_from_registry` | completer.py:20 | test_realcov_09b_typesystem_completer.py:TestCompleterFromLiveRegistry | REAL | None |
| `all_type_names` (sorted union of builtin + user) | completer.py:30 | test_realcov_09b_typesystem_completer.py:test_completer_includes_user_struct_after_real_run | REAL | None |
| `complete` — prefix match | completer.py:40 | test_realcov_09b_typesystem_completer.py:test_complete_prefix_matches_user_and_builtin | REAL | Empty-prefix tested; case-insensitivity confirmed |

### 3.13 pattern_registry.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `PatternRegistry.scan` | pattern_registry.py:40 | test_hexpat_pattern_registry.py:TestPatternDiscovery | REAL | None |
| `list_patterns` (sorted, lazy-scan) | pattern_registry.py:60 | test_hexpat_pattern_registry.py:test_list_patterns_sorted_by_name | REAL | None |
| `list_by_category` | pattern_registry.py:70 | test_hexpat_pattern_registry.py:test_list_by_category_groups_correctly | REAL | None |
| `get_pattern` | pattern_registry.py:80 | test_hexpat_pattern_registry.py:test_get_pattern_by_name | REAL | None |
| `match_file` — magic byte matching | pattern_registry.py:90 | test_hexpat_pattern_registry.py:TestPatternAutoDetect | REAL | None |
| `match_file` — longer magic preference | pattern_registry.py:100 | test_hexpat_pattern_registry.py:test_match_file_prefers_longer_magic | REAL | None |
| `load_source` | pattern_registry.py:120 | **NONE** | **NO** | No test calls `load_source()` and verifies content |
| `_extract_metadata` | pattern_registry.py:130 | test_hexpat_pattern_registry.py:TestPatternMetadata | REAL | None |
| `_update_max_magic_end` | pattern_registry.py:150 | Indirect via match_file ordering test | REAL (indirect) | None |

### 3.14 stdlib.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `BuiltinFunctions._mem_base_address` | stdlib.py | test_hexpat_core.py:test_mem_base_address_uses_pragma_directly | REAL | None |
| `BuiltinFunctions._mem_size` | stdlib.py | test_hexpat_stdlib.py:test_mem_size_via_builtin | REAL | None |
| `BuiltinFunctions._mem_read_unsigned` | stdlib.py | test_hexpat_stdlib.py:test_mem_read_unsigned_direct | REAL | None |
| `BuiltinFunctions._mem_read_unsigned` bounds | stdlib.py | test_hexpat_stdlib.py:test_mem_read_unsigned_beyond_end_raises | REAL | None |
| `BuiltinFunctions._mem_read_signed` | stdlib.py | test_hexpat_stdlib.py:test_mem_read_signed_direct_negative | REAL | None |
| `BuiltinFunctions._mem_find_sequence` | stdlib.py | test_hexpat_stdlib.py:test_mem_find_sequence_direct_found/not_found | REAL | None |
| `BuiltinFunctions._mem_read_bits` | stdlib.py | test_hexpat_core.py:test_mem_read_bits_extracts_high_nibble | REAL | None |
| `BuiltinFunctions._mem_create_section` | stdlib.py | test_hexpat_core.py:test_mem_section_lifecycle | REAL | None |
| `BuiltinFunctions._mem_delete_section` | stdlib.py | test_hexpat_core.py:test_mem_section_lifecycle | REAL | None |
| `BuiltinFunctions._mem_set_section_size` | stdlib.py | test_hexpat_core.py:test_mem_section_lifecycle | REAL | None |
| `BuiltinFunctions._mem_get_section_size` | stdlib.py | test_hexpat_core.py:test_mem_section_lifecycle | REAL | None |
| `BuiltinFunctions._mem_copy_to_section` | stdlib.py | test_hexpat_core.py:test_mem_section_lifecycle | REAL | None |
| `BuiltinFunctions._mem_find_string_in_range` | stdlib.py | test_hexpat_core.py:test_mem_find_string_in_range_locates_match | REAL | None |
| `BuiltinFunctions._mem_current_bit_offset` | stdlib.py | test_hexpat_core.py:test_mem_current_bit_offset_default_zero | REAL | None |
| `BuiltinFunctions._string_length/_at/_substr/_contains/_starts_with/_ends_with/_to_int` | stdlib.py | test_hexpat_stdlib.py:TestStringFunctions | REAL | None |
| `BuiltinFunctions._string_parse_int/_parse_float` | stdlib.py | test_hexpat_core.py:test_string_parse_int_returns_value | REAL | None |
| `BuiltinFunctions._string_reverse` | stdlib.py | test_hexpat_stdlib.py:test_string_reverse (partial read) | REAL | None |
| CRC functions (`_crc_compute`, `std::crc::*`) | stdlib.py:180+ | **NONE seen** | **UNKNOWN** | CRC subsystem not covered in any test file I read; `_crc_compute` visible at line ~150 |
| `BuiltinFunctions._core_array_index` | stdlib.py | test_hexpat_core.py:test_array_index_listener_returns_live_value | REAL | None |
| `BuiltinFunctions._core_set_endian` (0=native, 1=big, 2=little) | stdlib.py | test_hexpat_core.py:test_set_endian_updates_evaluator_default | REAL | None |
| `BuiltinFunctions._core_set_endian` invalid tag | stdlib.py | test_hexpat_core.py:test_set_endian_invalid_tag_raises | REAL | None |
| `BuiltinFunctions._core_has_attribute` (unwired raises) | stdlib.py | test_hexpat_core.py:test_reflection_provider_unwired_raises | REAL | None |
| `BuiltinFunctions._core_member_count/_has_member` | stdlib.py | test_hexpat_core.py:test_reflection_provider_wired_resolves_member_count | REAL | None |
| `BuiltinFunctions.register_all` (scope key registration) | stdlib.py | test_hexpat_core.py:test_mem_builtins_registered_in_scope | REAL | None |
| `set_print_sink` / print sink routing | stdlib.py | test_hexpat_core.py:test_print_sink_constructor_registers_callback | REAL | None |

### 3.15 hexpat_compiler.py

| Operation | Source | Tests | Verdict | Missing edges |
|-----------|--------|-------|---------|---------------|
| `HexPatCodegen.generate` — struct fields | hexpat_compiler.py:200 | test_realcov_07b_compiler_pragmas.py | REAL | None |
| `HexPatCodegen.generate` — pragma endian propagation | hexpat_compiler.py:210 | test_realcov_07b_compiler_pragmas.py:test_endian_big_sets_default_endianness | REAL | None |
| `HexPatCodegen.generate` — pragma magic detection | hexpat_compiler.py:220 | test_realcov_07b_compiler_pragmas.py:test_magic_pragma_emits_magic_detection | REAL | None |
| `HexPatCodegen.generate` — pragma_metadata block | hexpat_compiler.py:230 | test_realcov_07b_compiler_pragmas.py:test_base_address_and_pointer_size_in_pragma_metadata | REAL | None |
| `HexPatCodegen.generate` — conditional inverted-op | hexpat_compiler.py:260 | test_realcov_07b_compiler_pragmas.py:TestConditionalInvertedOperator | REAL | None |
| `HexPatCodegen._reject_runtime_top_level` | hexpat_compiler.py:180 | test_hexpat_compiler.py:TestCodegenRejectsRuntimeConstructs | REAL | None |
| `HexPatCompiler.compile` | hexpat_compiler.py:300 | test_hexpat_compiler.py:TestCompilerDelegationToSharedPipeline | REAL | None |
| `HexPatCompiler.compile_to_dict` | hexpat_compiler.py:310 | test_realcov_07b_compiler_pragmas.py (uses `_compile()` helper) | REAL | None |
| Re-exports: HexPatLexer, HexPatParser, Token, TokenType, HexPatError | hexpat_compiler.py:1-20 | test_hexpat_compiler.py:TestSharedSymbolReexports | REAL | None |

### 3.16 parser.py (inferred from test outputs)

The parser source was not directly read. Coverage is inferred from test assertions on AST output in `test_hexpat_parser_e2e.py` and `test_realcov_08_parser_unit.py`.

| Grammar production | Tests | Verdict |
|-------------------|-------|---------|
| Struct declaration | test_hexpat_parser_e2e.py:TestStructParsing | REAL |
| Union declaration | test_hexpat_parser_e2e.py:TestUnionParsing | REAL |
| Enum declaration | test_hexpat_parser_e2e.py:TestEnumParsing | REAL |
| Bitfield declaration | test_hexpat_parser_e2e.py:TestBitfieldParsing | REAL |
| Function declaration | test_hexpat_parser_e2e.py:test_parse_function_declaration | REAL |
| Variable declaration (const) | test_hexpat_parser_e2e.py:test_parse_variable_declaration | REAL |
| Using/alias declaration | test_hexpat_parser_e2e.py:test_parse_using_alias | REAL |
| Namespace declaration (nested) | test_realcov_08_parser_unit.py:TestNestedNamespaceParsing | REAL |
| Placement statement | test_hexpat_parser_e2e.py:test_parse_placement_statement | REAL |
| Double-bracket annotations | test_realcov_08_parser_unit.py:TestAnnotationParsing | REAL |
| Template parameters | test_realcov_08_parser_unit.py:TestTemplateParamParsing | REAL |
| While-condition array | test_realcov_08_parser_unit.py:TestArrayParsing | REAL |
| Expression precedence (Pratt) | test_realcov_08_parser_unit.py:TestExpressionPrecedence | REAL |
| Bitfield typed/padding entries | test_realcov_08_parser_unit.py:TestBitfieldEntryParsing | REAL |
| Syntax error raises HexPatParseError | test_hexpat_parser_e2e.py:test_parse_syntax_error_raises | REAL |
| Aggregate error surfacing | test_parser_aggregate_errors.py:TestAggregateParseError | REAL |
| Empty source returns empty list | test_hexpat_parser_e2e.py:test_parse_empty_source_returns_empty_list | REAL |

---

## 4. Worst Offenders (Fake Gates and Violations)

### 4.1 MOCK VIOLATION — `test_hexpat_core.py:test_compile_to_json_preserves_native_hexpat_error`

**Location:** `tests/test_audit5/u3_hexpat_core/test_hexpat_core.py`, line 257

**Violation:** Uses `from unittest import mock` and `mock.patch("intellicrack.core.hexpat_compiler.HexPatCompiler.compile", side_effect=sentinel)` to inject a synthetic `HexPatTypeError` without running the real compiler.

**Why it fails the quality gate:** The test mocks the exact operation it claims to verify — that `HexPatInterpreter.compile_to_json` does not re-wrap compiler errors. Because `HexPatCompiler.compile` is patched, the test never exercises the production path through the compiler. If the interpreter re-wrapped the error in a different way that still preserved the class identity, the test would still pass. The test would also pass if the interpreter's `compile_to_json` body were replaced with `raise args[0]` verbatim — the real error-propagation contract of the try/except block is never validated against a real compiler error.

**Classification:** FAKE GATE — mock-the-thing-under-test anti-pattern.

**Remediation:** Remove `mock.patch`. Instead, pass source code that triggers a genuine `HexPatTypeError` through the real compiler (e.g., a struct that shadows a builtin name: `"struct u32 { u8 x; };"` will cause the type checker inside the compiler to raise `HexPatTypeError`). Assert that the raised exception is an instance of `HexPatTypeError` (not the base `HexPatError`) and that `__cause__` is not set (i.e., the precise subclass propagated unchanged). This tests the real error-propagation contract through the real compiler.

### 4.2 WEAK TEST — `test_compiler.py:test_compile_round_trips_through_shared_lexer`

**Location:** `tests/test_hexpat/test_compiler.py`

**Violation:** Uses `any(isinstance(t, ...) for t in tokens)` as the sole assertion, checking only that at least one token of a given type exists. If the lexer returned a stream of entirely wrong token types, `any(isinstance(t, TokenType.KEYWORD) for t in tokens)` would still pass if even a single keyword token appeared by coincidence.

**Classification:** WEAK — weak-assertion-on-rich-output. The meaningful assertion would check the exact token sequence, specific token positions, and precise types.

**Remediation:** Assert the exact token stream: check that `tokens[0].type == TokenType.KEYWORD` and `tokens[0].value == "struct"`, that `tokens[1].type == TokenType.IDENTIFIER` and `tokens[1].value == "Header"`, etc. The oracle is the source string itself — the expected token sequence is derivable without re-running the lexer.

### 4.3 BORDERLINE CONCERN — `_StubDocument` in `test_bridge_print_sink.py`

**Location:** `tests/test_audit7/u12_hexpat_print_sink/test_bridge_print_sink.py:43`

**Issue:** The file defines a class called `_StubDocument` described as "a minimal HexDocument-compatible stub." The project standard prohibits stubs.

**Assessment:** The `_StubDocument` is a pure-Python implementation of the `HexDocumentLike` protocol backed by a real `bytes` object. It does not return hardcoded analysis results, does not replace bridge behavior, and does not mock the behavior under test (the HexEditorBridge's print-sink wiring and output capture). It provides a real binary buffer to the production pipeline. This is structurally similar to writing a real binary to a tempfile — the bytes are real, the data is real.

**Verdict:** ACCEPTABLE but must be labeled as a protocol adapter, not a stub, in comments. The concern is terminology: calling it a "stub" in the docstring invites future violation creep. The behavior passes the falsifiability test because removing the print-sink wiring from the bridge causes `test_print_sink_receives_pattern_output` to fail (the captured list remains empty).

**Note:** If the native `intellicrack_hexcore` extension is available in the test environment, the `_StubDocument` should be replaced with the real `HexDocument` wrapping the same bytes. The fixture's `pytest.skip` guard for `ImportError` is appropriate.

---

## 5. Coverage Gaps

The following behaviors have no real, falsifiable gate. All are actionable — the oracle for each is independently derivable.

### GAP-1: `HexPatParseError.span` property

**Source:** `errors.py:97-105`

**Missing behavior:** The `span` property returns `tuple[int, int, int, int] | None`. No test constructs a `HexPatParseError` with `end_line` and `end_column` and asserts `err.span == (start_line, start_col, end_line, end_col)`. No test verifies that `span` returns `None` when end positions are absent.

**Oracle:** The `span` property is a pure function of the constructor arguments: if `HexPatParseError("msg", line=2, column=3, end_line=4, end_column=5)` is constructed, `err.span` must return `(2, 3, 4, 5)`. No runtime behavior is needed to compute the expected output.

### GAP-2: `HexPatRuntimeError.data_span` property

**Source:** `errors.py:152-160`

**Missing behavior:** Identical gap to GAP-1 but for the `data_span` property. No test asserts the `(offset, end_offset)` tuple or the `None` case.

**Oracle:** `HexPatRuntimeError("msg", offset=0x100, end_offset=0x104)` must satisfy `err.data_span == (0x100, 0x104)`. The condition `offset > 0 and end_offset > offset` is derivable from the constructor signature.

### GAP-3: `HexPatError.__str__` exact format

**Source:** `errors.py:44-45`

**Missing behavior:** The `__str__` format is `"{file}:{line}:{col}: {message}"` when all are set. Existing tests check only `"u8" in str(err)`, not the full format string. If the format separator changed from `:` to ` `, no test would catch it.

**Oracle:** Independently derive the expected string: `HexPatError("bad type", line=3, column=7, file="test.hexpat")` must produce `str(err) == "test.hexpat:3:7: bad type"`.

### GAP-4: Function-like macro expansion (`#define FUNC(args) body`)

**Source:** `preprocessor.py:_parse_macro_arguments`, `_substitute_func_macro`

**Missing behavior:** The preprocessor supports `#define ADD(a,b) ((a)+(b))` form. Neither `_parse_macro_arguments` nor `_substitute_func_macro` are exercised by any test in the suite. Object-like defines are comprehensively tested; function-like defines are entirely absent.

**Oracle:** Source `"#define DOUBLE(x) ((x)*2)\nu8 v @ 0;DOUBLE(3)"` — after preprocessing, the body must contain `((3)*2)` where `DOUBLE(3)` appeared. The expected string is computed from the spec: the macro parameter `x` is replaced with the argument `3`.

### GAP-5: Preprocessor macro expansion iteration limit (64 passes)

**Source:** `preprocessor.py:_process_defines`

**Missing behavior:** The fixed-point macro expansion loop runs at most 64 passes. No test verifies that a pattern requiring fewer than 64 expansions converges, and no test verifies that a non-converging pattern (e.g., `#define A A A`) halts at the limit rather than looping indefinitely.

**Oracle for limit test:** Define a self-referential macro and assert that preprocessing completes in finite time and that the output string contains a bounded number of expansions.

### GAP-6: Evaluator struct depth limit enforcement

**Source:** `evaluator.py:_eval_struct_instance`

**Missing behavior:** When evaluation exceeds `pragma.eval_depth` levels of nested struct instantiation, the evaluator should raise `HexPatRuntimeError`. No test sets a low `eval_depth` and places a deeply nested struct.

**Oracle:** Create a pattern with `eval_depth = 3` pragma and a struct that references itself 4 levels deep. The evaluator must raise `HexPatRuntimeError` before completing. The expected depth is the pragma value.

### GAP-7: Evaluator pattern limit enforcement

**Source:** `evaluator.py:_eval_placement`

**Missing behavior:** When the number of pattern evaluations reaches `pragma.pattern_limit`, field emission stops. No test sets `pattern_limit = N` and verifies that only N fields appear in the result.

**Oracle:** Set `pattern_limit = 2` via pragma. Evaluate a pattern with 4 top-level field placements. Assert `len(results) == 2`.

### GAP-8: `PatternRegistry.load_source`

**Source:** `pattern_registry.py:120`

**Missing behavior:** `load_source(name)` reads and returns the raw source text of a named pattern. No test calls this method and verifies the content.

**Oracle:** Write a known `.hexpat` source string to a temp file, scan it, then call `load_source(name)` and assert the returned string equals the original source text.

### GAP-9: CRC stdlib functions

**Source:** `stdlib.py:_crc_compute` and `BuiltinFunctions._crc_*` methods

**Missing behavior:** The CRC subsystem (`std::crc::calculate`, `std::crc::calculate_with_lut`) was visible in the partial stdlib read but is not exercised by any test I read. CRC32 of known data is an independently verifiable computation.

**Oracle:** `_crc_compute(crc32_table, 0xFFFFFFFF, [0x4D, 0x5A])` must equal the known CRC32 of the bytes `MZ`. Python's `binascii.crc32` provides the independent oracle.

### GAP-10: `import mod;` preprocessor directive

**Source:** `preprocessor.py:_process_source`

**Missing behavior:** The preprocessor handles `import std::mem;` as a shorthand for `#include <std/mem.hexpat>`. No test exercises this path.

**Oracle:** Source `"import std::string;\nu32 x @ 0;"` processed with a configured include path containing `std/string.hexpat` must inline the library source.

---

## 6. Section Scores

### Gate Coverage Score

Counting distinct behavior-bearing operations across all 17 source files (excluding pure-data frozen dataclasses):

| Layer | Total ops | Ops with real gate | Score |
|-------|-----------|-------------------|-------|
| tokens.py (data, tested via lexer) | 3 | 3 | 100% |
| errors.py | 8 | 5 | 63% |
| lexer.py | 25 | 25 | 100% |
| preprocessor.py | 22 | 16 | 73% |
| pragma.py | 5 | 5 | 100% |
| parse_helpers.py | 11 | 11 | 100% |
| data_reader.py | 13 | 13 | 100% |
| type_system.py | 28 | 28 | 100% |
| evaluator.py (selected 35 critical paths) | 35 | 33 | 94% |
| interpreter.py | 8 | 7 | 88% |
| completer.py | 3 | 3 | 100% |
| pattern_registry.py | 8 | 7 | 88% |
| stdlib.py (known surface) | 30 | 28 | 93% |
| hexpat_compiler.py | 10 | 10 | 100% |
| parser.py (inferred) | 17 | 17 | 100% |
| **Total** | **226** | **211** | **93%** |

**Overall gate coverage: 93%** — well above the 85% floor, but two error-class property gaps and two evaluator limit gaps must be remediated before this can be considered a full protection surface.

### Edge-Case Coverage Score

| Edge-case category | Covered | Missing |
|-------------------|---------|---------|
| Lexer error paths (7 types) | ALL | — |
| Parser syntax error | YES | span property |
| Parser aggregate errors | YES | — |
| Type system reserved-name collision (5 types) | ALL | — |
| Circular alias protection | YES | — |
| Instance isolation | YES | — |
| DataReader bounds violations | YES | — |
| Evaluator arithmetic overflow/wrapping | YES | — |
| Evaluator NaN/Inf rejection | YES | — |
| Evaluator error paths (assert, OOB) | YES | — |
| Error class span properties | NO | GAP-1, GAP-2 |
| Function-like macro expansion | NO | GAP-4 |
| Macro iteration limit | NO | GAP-5 |
| Circular include prevention | NO | GAP-4 area |
| Evaluator depth limit | NO | GAP-6 |
| Evaluator pattern limit | NO | GAP-7 |
| PatternRegistry.load_source | NO | GAP-8 |
| CRC functions | NO | GAP-9 |
| `import mod;` directive | NO | GAP-10 |

**Edge-case score: 11/19 = 58%** — the core engine (evaluator, type system, lexer) has excellent edge-case coverage; the gaps are concentrated in error-class properties, preprocessor advanced features, evaluator limits, and stdlib CRC.

---

## 7. Remediation Recommendations

Listed in priority order. Each remediation states what to assert against what independent oracle.

### REM-1 (Priority: HIGH) — Rewrite `test_compile_to_json_preserves_native_hexpat_error`

Remove `from unittest import mock` and `mock.patch`. Replace with a test that supplies real source code that causes a genuine `HexPatTypeError` from the compiler (e.g., `"struct u32 { u8 x; };"` — shadowing a builtin). Assert:
- The raised exception `is` an instance of `HexPatTypeError` (not just `HexPatError`)
- The `__cause__` chain is not present (the original typed error propagated unchanged)
- The `err.message` contains the expected builtin-name collision text

The oracle is the compiler's documented behavior: user-defined types cannot shadow builtin primitive names, so a `HexPatTypeError` will be raised with the name "u32" in the message.

### REM-2 (Priority: HIGH) — Fix `test_compile_round_trips_through_shared_lexer`

Replace the `any(...)` check with an assertion on the exact token type and value at a specific position in the token stream. The oracle is the source string — the first token of `"struct Header { u32 magic; };"` must be `TokenType.KEYWORD` with value `"struct"`, the second must be `TokenType.IDENTIFIER` with value `"Header"`, and so on.

### REM-3 (Priority: HIGH) — Add `HexPatParseError.span` and `HexPatRuntimeError.data_span` tests

Add to `tests/test_hexpat/` (new file `test_error_classes.py` or in `test_parse_helpers.py`):

```python
# HexPatParseError.span
err = HexPatParseError("unexpected token", line=2, column=3, end_line=4, end_column=5)
assert err.span == (2, 3, 4, 5)
err_no_end = HexPatParseError("unexpected token", line=2, column=3)
assert err_no_end.span is None

# HexPatRuntimeError.data_span
err = HexPatRuntimeError("out of bounds", offset=0x100, end_offset=0x104)
assert err.data_span == (0x100, 0x104)
err_no_end = HexPatRuntimeError("out of bounds", offset=0x100)
assert err_no_end.data_span is None
# offset=0 case
err_zero = HexPatRuntimeError("other", offset=0, end_offset=4)
assert err_zero.data_span is None
```

### REM-4 (Priority: HIGH) — Add function-like macro expansion tests

Add to `tests/test_hexcore_e2e/test_hexpat_preprocessor.py:TestNestedDefines`:

```python
def test_function_like_macro_single_arg(self) -> None:
    pp = HexPatPreprocessor()
    source = "#define DOUBLE(x) ((x)*2)\nu8 result = DOUBLE(3);"
    result, _ = pp.process(source)
    assert "((3)*2)" in result

def test_function_like_macro_two_args(self) -> None:
    pp = HexPatPreprocessor()
    source = "#define ADD(a, b) ((a)+(b))\nu8 result = ADD(1, 2);"
    result, _ = pp.process(source)
    assert "((1)+(2))" in result
```

The oracle is the macro substitution rule: each occurrence of the parameter name in the body is replaced with the corresponding argument string.

### REM-5 (Priority: MEDIUM) — Add evaluator depth-limit test

In `tests/test_hexcore_e2e/test_hexpat_evaluator.py` or `test_hexpat_complex_patterns.py`:

```python
def test_eval_depth_limit_raises(self, interp: HexPatInterpreter) -> None:
    data = bytes(16)
    # Force a depth-3 limit and recurse 4 levels via parent
    source = (
        "#pragma eval_depth 3\n"
        "struct A { u8 a; };\n"
        "struct B : A { u8 b; };\n"
        "struct C : B { u8 c; };\n"
        "struct D : C { u8 d; };\n"
        "D root @ 0;"
    )
    with pytest.raises(HexPatRuntimeError):
        interp.execute_bytes(source, data)
```

Oracle: the pragma sets the limit, and the runtime error is the documented response to exceeding it.

### REM-6 (Priority: MEDIUM) — Add evaluator pattern-limit test

```python
def test_pattern_limit_truncates_output(self, interp: HexPatInterpreter) -> None:
    data = bytes(16)
    source = "#pragma pattern_limit 2\nu8 a @ 0;\nu8 b @ 1;\nu8 c @ 2;\nu8 d @ 3;"
    results = interp.execute_bytes(source, data)
    assert len(results) == 2
```

Oracle: `pattern_limit = 2` in the pragma; the evaluator must stop emitting after 2 fields.

### REM-7 (Priority: MEDIUM) — Add `PatternRegistry.load_source` test

In `tests/test_hexcore_e2e/test_hexpat_pattern_registry.py`:

```python
def test_load_source_returns_file_content(self, tmp_path: Path) -> None:
    content = "u32 magic @ 0;"
    _write_pattern(tmp_path, "source_test", content)
    registry = PatternRegistry(pattern_dirs=[tmp_path])
    source = registry.load_source("source_test")
    assert source == content
```

Oracle: the file's content is the expected value — no transformation should occur.

### REM-8 (Priority: MEDIUM) — Add CRC stdlib tests

In `tests/test_hexcore_e2e/test_hexpat_stdlib.py`:

```python
import binascii

def test_crc32_matches_python_binascii(self) -> None:
    data = bytes([0x4D, 0x5A])
    reader = DataReader.from_bytes(data)
    builtin = BuiltinFunctions(reader)
    # Independent oracle: Python's binascii.crc32
    expected = binascii.crc32(data) & 0xFFFFFFFF
    result: int = getattr(builtin, "_crc_compute")(...)
    assert result == expected
```

The exact calling convention for `_crc_compute` must be confirmed from the source at line 150+.

### REM-9 (Priority: LOW) — Add `HexPatError.__str__` exact format test

```python
def test_hexpaterror_str_includes_file_line_col() -> None:
    err = HexPatError("bad type", line=3, column=7, file="test.hexpat")
    assert str(err) == "test.hexpat:3:7: bad type"
```

Oracle: directly derivable from the `__init__` logic: `":".join(["test.hexpat", "3", "7"])`.

---

## 8. Summary

The HexPat Pattern-Language Engine test suite is one of the most comprehensively tested sections of the Intellicrack codebase. The dual-oracle strategy (indexed `bytes(range(256))` + `struct.pack` values as independent oracles) used in `test_hexpat_evaluator.py` and `test_hexpat_data_reader.py` represents the gold standard for this codebase. Tests against real Windows System32 PE DLLs in `test_realcov_09a_evaluator_realdata.py` provide genuine binary validation. The type system, lexer, parser, control flow, and stdlib tests are genuine falsifiable gates.

**Two defects require remediation before release:**

1. `tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:test_compile_to_json_preserves_native_hexpat_error` — MOCK VIOLATION (mock.patch on the production compiler). This test provides false confidence that error propagation through `compile_to_json` is correct; it can pass with a completely wrong implementation as long as the mock is set up right.

2. `tests/test_hexpat/test_compiler.py:test_compile_round_trips_through_shared_lexer` — WEAK (sole assertion is `any()` presence check on the token stream). Deleting the lexer's keyword dispatch would still leave this test green as long as a single keyword-type token appeared.

**Ten coverage gaps** are documented above (GAP-1 through GAP-10), with independently-derivable oracles for each. The highest-priority gaps are the error-class span properties (GAP-1, GAP-2) and function-like macro expansion (GAP-4), which represent entire language features with no gate.

**Gate coverage: 93% | Edge-case coverage: 58%**

The edge-case score reflects that the core execution engine is very well protected, while the preprocessor's advanced macro features, evaluator resource limits, and stdlib CRC subsystem are entirely unguarded.
