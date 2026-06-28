# Group 01 Verification Report

**Sections covered:** section-01-bridge-framework.md (full), section-05-hex-editor-bridge.md (full), section-06-hexpat-engine.md (full)

**Auditor:** GROUP 01 (test-reviewer agent)

**Date:** 2026-06-27

---

## Methodology

All non-REAL rows were enumerated independently from the source audit tables. Findings were verified against the current `tests/` tree using rg/Glob/Read. The key new remediation files checked:

- `tests/test_bridges/test_named_pipe_client_errors_wave2d.py` — named pipe error branches
- `tests/test_bridges/test_hex_editor_bridge_methods_wave4.py` — hex bridge zero-coverage methods
- `tests/test_hexpat/test_hexpat_tails_wave4.py` — HexPat error classes, macro expansion, limits, CRC
- `tests/test_bridges/test_schemas.py` (updated) — provider schema format discrimination
- `tests/test_hexcore_e2e/test_bridge_ai_context.py` (updated) — AI context exact assertions
- `tests/test_hexcore_e2e/test_bridge_html_export_largefile.py` (updated) — get_memory_usage
- `tests/test_hexcore_e2e/test_bridge_display.py` (updated) — remove_highlight_rule False path
- `tests/test_hexcore_e2e/test_hexpat_pattern_registry.py` (updated) — load_source
- `tests/test_audit5/u3_hexpat_core/test_hexpat_core.py` (updated) — compile_to_json real source

---

## Finding Table

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation) |
|---|---|---|---|---|
| **SECTION 01 — Bridge Framework** | | | | |
| 01 | `TOOL_CAPABILITY_MAP` scripting family (base.py:74-82) | WEAK GATE | NOT_RESOLVED | Only tested via integration (test_base.py:493-514). No direct `TOOL_CAPABILITY_MAP.get("execute_script") == "scripting"` assertion in `TestToolCapabilityMapCompleteness`. Removing the scripting entries from the map would not fail any test in that class. |
| 02 | `TOOL_CAPABILITY_MAP` decompilation family (base.py:62) | WEAK GATE | NOT_RESOLVED | Same: `decompile` tested only via integration (test_base.py:563-581). No direct map-value assertion. |
| 03 | `BinaryOperationsBridge.__init__` capability values (base.py:1046-1054) | NO COVERAGE | NOT_RESOLVED | No concrete subclass test exercises capability flags. Grep confirms no `supports_static_analysis` or `supports_patching` assertion against a `BinaryOperationsBridge` subclass instance anywhere in tests/. |
| 04 | `resolve()` warning log on unknown attribute (lazy.py:60) | NO COVERAGE | NOT_RESOLVED | No test captures `_logger.warning("lazy_resolve_unknown_attribute", ...)`. The AttributeError branch is tested for the exception itself but log emission is unverified. |
| 05 | `resolve()` TypeError for non-bridge/non-installer (lazy.py:68-71) | NO COVERAGE | NOT_RESOLVED | No test constructs a `LAZY_EXPORTS` entry resolving to a non-class or non-bridge attribute. The branch `raise TypeError(f"lazy export {name!r} ...")` is never exercised. |
| 06 | `build_schema_property` array+object recursive branch (schemas.py:258-267) | NO COVERAGE | NOT_RESOLVED | `_build_array_items` when `element_type == "object"` and `param.item_properties` is set: no test in test_schemas.py or test_bridges_core_audit1.py exercises this path. |
| 07 | `validate_tool_parameter` array with unrecognized items_type (schemas.py:419-422) | NO COVERAGE | NOT_RESOLVED | `ValidationError("Array parameter has unrecognized items_type …")` branch never reached. No test constructs an array parameter with an unrecognized items_type string. |
| 08 | `validate_tool_parameter` array of objects without item_properties (schemas.py:427-434) | NO COVERAGE | NOT_RESOLVED | `ValidationError("Array of objects requires item_properties …")` branch never reached. |
| 09 | `get_schema_for_provider` — OLLAMA (schemas.py:691) | WEAK GATE | RESOLVED | test_schemas.py:711-755 · now asserts `schema.get("type") == "function"` and `"input_schema" not in schema` for all OpenAI-route providers including OLLAMA · mutation routing to `to_anthropic_schema` produces `"input_schema"` key → test fails |
| 10 | `get_schema_for_provider` — OPENROUTER (schemas.py:693) | WEAK GATE | RESOLVED | Same test and oracle as #09 |
| 11 | `get_schema_for_provider` — HUGGINGFACE (schemas.py:695) | WEAK GATE | RESOLVED | Same test and oracle as #09 |
| 12 | `get_schema_for_provider` — GROK (schemas.py:697) | WEAK GATE | RESOLVED | Same test and oracle as #09 |
| 13 | `get_schema_for_provider` — LOCAL_TRANSFORMERS (schemas.py:699) | WEAK GATE | RESOLVED | Same test and oracle as #09 |
| 14 | `_assert_never` (schemas.py:28-48) | NO COVERAGE | NOT_RESOLVED | Deliberately unreachable: the exhaustive `if/elif/else` chain in `get_schema_for_provider` prevents this branch from executing in production. No test can exercise it. Architecturally dead-code-by-design but no test exists per protocol requirement. |
| 15 | `connect()` already-connected no-op (npc.py:198-199) | NO COVERAGE | RESOLVED | test_named_pipe_client_errors_wave2d.py:325-367 · oracle: `_open_handle` call count == 1 after two `connect()` calls · mutation: removing the `if self._handle is not None: return` guard causes count == 2 → assertion fails |
| 16 | `send_command()` `_read_failure` pre-send guard (npc.py:388-390) | NO COVERAGE | RESOLVED | test_named_pipe_client_errors_wave2d.py:376-393 · `pytest.raises(ToolError, match=r"Pipe reader failed")` with synthetic `_read_failure` set · mutation: removing guard lets send proceed and await a dead future → ToolError never raised |
| 17 | `_reader_loop` response missing int id warning (npc.py:480-485) | NO COVERAGE | RESOLVED | test_named_pipe_client_errors_wave2d.py:542-580 · `_LogSink` captures `pipe_response_missing_id` at `level == "warning"` with `msg_type == "response"` · mutation: removing the `isinstance(request_id_obj, int)` guard → event never logged |
| 18 | `_reader_loop` no waiter for response id (npc.py:488-492) | NO COVERAGE | RESOLVED | test_named_pipe_client_errors_wave2d.py:589-627 · `_LogSink` captures `pipe_response_no_waiter` at `level == "debug"` with `request_id == 77777` · mutation: removing the `else` debug log → event never logged |
| 19 | `_send_message` oversized payload (npc.py:541-543) | NO COVERAGE | RESOLVED | test_named_pipe_client_errors_wave2d.py:402-419 · `pytest.raises(ToolError, match=r"Message exceeds maximum size")` with 10-byte limit and 200-char payload · mutation: removing size check allows frame write |
| 20 | `_read_message` malformed JSON body (npc.py:569-573) | NO COVERAGE | RESOLVED | test_named_pipe_client_errors_wave2d.py:484-504 · `pytest.raises(ToolError, match=r"Invalid JSON payload")` with `b"not-valid-json{{"` body · mutation: removing except handler lets JSONDecodeError propagate uncontrolled |
| 21 | `_read_message` invalid length prefix (npc.py:563-565) | NO COVERAGE | RESOLVED | test_named_pipe_client_errors_wave2d.py:428-447 (length=0) and :456-475 (length>max) · `pytest.raises(ToolError, match=r"Invalid message length")` · mutation: removing bounds check silently reads zero or unbounded bytes |
| 22 | `_read_message` non-dict payload (npc.py:575-577) | NO COVERAGE | RESOLVED | test_named_pipe_client_errors_wave2d.py:513-533 · `pytest.raises(ToolError, match=r"Unexpected message payload type")` with JSON array body · mutation: removing isinstance check causes AttributeError in caller |
| 23 | `_read_exact` timeout raises ToolError (npc.py:597-605) | NO COVERAGE | NOT_RESOLVED | No isolated test drives `_read_exact` into the timeout path and asserts ToolError. The wave2d file does not cover this branch. |
| 24 | `_cancel_io` (npc.py:869-882) | NO COVERAGE | NOT_RESOLVED | No test asserts `CancelIoEx` is called, that the log entries are emitted, or that pending I/O is unblocked. The method is exercised indirectly by close()/timeout but never asserted directly. |
| 25 | `bridges/__init__.py __dir__` (\_\_init\_\_.py:90-96) | NO COVERAGE | NOT_RESOLVED | No test calls `dir(bridges_pkg)` and asserts that lazy-export names and `__all__` entries appear. The sorted-union logic is entirely untested. |
| **SECTION 05 — Hex Editor Bridge** | | | | |
| 26 | `get_context_for_ai` WEAK assertions (hex_editor.py:4977) | WEAK | RESOLVED | test_bridge_ai_context.py:51-74 (top-level keys + exact values), :92-103 (bookmarks == []), :105-122 (bookmark fields), :124-141 (size == stat().st_size) · oracle: pe_binary.stat().st_size, expected field values · mutations caught: wrong size, wrong bookmark data |
| 27 | `test_in_sandbox` — NONE (hex_editor.py:5117) | NONE | RESOLVED | test_hex_editor_bridge_methods_wave4.py:TestTestInSandbox (9 tests) · covers: no-doc, no-file-path, no-registry, no-sandbox-bridge, no-run-binary, exact binary_path, args splitting, sandbox_type/time_limit forwarding, result passthrough · oracle: known _FakeSandboxBridge call records |
| 28 | `insert_bytes` bridge level — NONE (hex_editor.py:5278) | NONE | RESOLVED | test_hex_editor_bridge_methods_wave4.py:TestInsertBytes (7 tests) · oracle: post-insert read_all bytes (independent concatenation), bridge.document.length() · mutation: off-by-one in insert offset produces wrong byte sequence |
| 29 | `delete_bytes` bridge level — NONE (hex_editor.py:5304) | NONE | RESOLVED | test_hex_editor_bridge_methods_wave4.py:TestDeleteBytes (5 tests) · oracle: post-delete read_all bytes (independent concatenation), length reduction by exact count · mutation: wrong offset or count leaves wrong bytes |
| 30 | `get_selection` exact tuple at bridge level (hex_editor.py:5928) | WEAK | NOT_RESOLVED | test_selection_dispatch.py:270 asserts exact `(start, end)` but against `_StubBridge.get_selection()` (a hand-written stub), not `HexEditorBridge.get_selection()` (hex_editor.py:5928). The real bridge `get_selection()` is only tested for the `is None` initial case (test_bridge_concurrent.py:153). Missing: a test that calls the real `HexEditorBridge.select_range(4, 12)` then asserts `bridge.get_selection() == (4, 12)`. |
| 31 | `inspect_data_at` — NONE (hex_editor.py:6336) | NONE | RESOLVED | test_hex_editor_bridge_methods_wave4.py:TestInspectDataAt (7 tests) · oracle: struct.unpack("<B/h/H/i/I/q/Q/>H/>I/>Q/>q") for all numeric fields · mutation: swapping uint32_le with uint32_be returns wrong value |
| 32 | `get_byte_statistics` — NONE (hex_editor.py:6381) | NONE | RESOLVED | test_hex_editor_bridge_methods_wave4.py:TestGetByteStatistics (6 tests) · oracle: known histogram {0x41:3, 0x42:2, 0x43:1} for _STATS_DATA, Shannon entropy formula · mutation: wrong count for any byte shifts histogram and entropy |
| 33 | `get_content_classification` — NONE (hex_editor.py:6662) | NONE | RESOLVED | test_hex_editor_bridge_methods_wave4.py:TestGetContentClassification (7 tests) · oracle: documented classification constants (0=null, 1=plaintext, 2=structured, 3=encrypted) · mutation: returning wrong constant for known content fails exact equality |
| 34 | `get_pe_imports` WEAK coexisting gate (hex_editor.py:8670) | WEAK + REAL | RESOLVED | Real gate exists at test_realcov_01_hex_editor_pe_real.py via pefile oracle cross-validation. The fake gate at test_hex_editor_top_audit1.py:496 (`isinstance(result, list)`) still exists alongside. The operation is covered by a real gate; the fake test is surplus but does not negate the real coverage. |
| 35 | `get_memory_usage` WEAK (hex_editor.py:8544) | WEAK | RESOLVED | test_bridge_html_export_largefile.py:177-199 · `result["usage_bytes"] == len(payload)` (oracle: file bytes), `result["chunk_size"] == chunk_hint` (oracle: set value) · mutation: returning 0 for usage_bytes fails exact equality |
| 36 | `remove_highlight_rule_state` False return (hex_state.py:373) | WEAK | RESOLVED | test_bridge_display.py:179-186 · `assert not removed` after calling `bridge.remove_highlight_rule("nonexistent-rule-id-00000000")` · exercises state method's False path through production bridge code · mutation: always returning True causes `assert not removed` to fail |
| **SECTION 06 — HexPat Pattern-Language Engine** | | | | |
| 37 | `HexPatError.__str__` exact format (errors.py:44-45) | WEAK | NOT_RESOLVED | test_hexpat_tails_wave4.py:53-55 checks `"[span 2:4-2:10]" in str(err)` on `HexPatParseError` (a subclass span annotation), not the full `"file:line:col: message"` format of the base `HexPatError.__str__`. Missing: `assert str(HexPatError("bad type", line=3, column=7, file="test.hexpat")) == "test.hexpat:3:7: bad type"`. |
| 38 | `HexPatParseError.__init__` with span WEAK (errors.py:63-94) | WEAK | RESOLVED | test_hexpat_tails_wave4.py:TestHexPatParseErrorSpan:37-73 · asserts exact span tuple, span is None for missing end, attribute values · oracle: constructor argument values · mutation: swapping start/end columns returns wrong tuple |
| 39 | `HexPatParseError.span` property — NO (errors.py:97-105) | NO | RESOLVED | test_hexpat_tails_wave4.py:37-73 · `err.span == (3, 7, 3, 15)` exact tuple, `err.span is None` for missing end positions · independent oracle: known constructor arguments |
| 40 | `HexPatRuntimeError.data_span` property — NO (errors.py:152-160) | NO | RESOLVED | test_hexpat_tails_wave4.py:TestHexPatRuntimeErrorDataSpan:79-120 · `err.data_span == (0x10, 0x20)`, None for offset=0, None for end<=offset · oracle: known constructor args and the condition `offset > 0 and end_offset > offset` |
| 41 | `_process_source` function-like `#define FUNC(args)` — NO (preprocessor.py:130) | NO | RESOLVED | test_hexpat_tails_wave4.py:TestFunctionLikeMacroExpansion:127-174 · asserts `"((3) + (4))" in out` and `"ADD" not in out` · oracle: macro substitution spec: param name replaced with argument text · mutation: not expanding leaves `ADD(3, 4)` unexpanded |
| 42 | `_process_source` `import mod;` directive — NO (preprocessor.py:220) | NO | NOT_RESOLVED | No test exercises `import std::mem;` style import directive. The path that converts `import X::Y;` to `#include <X/Y.hexpat>` is entirely untested. |
| 43 | `_resolve_include` circular import prevention — NO (preprocessor.py:290) | NO | NOT_RESOLVED | No test verifies that A→B→A circular include is detected and prevented. Only `#pragma once` double-include prevention is tested (test_hexpat_preprocessor.py:198). |
| 44 | `_process_defines` 64-pass limit — PARTIAL (preprocessor.py:320) | PARTIAL | NOT_RESOLVED | No test verifies the 64-pass convergence boundary. Only convergence on simple nested defines is tested. A non-converging macro that loops more than 64 times is not verified to halt. |
| 45 | `_parse_macro_arguments` — NO (preprocessor.py:420) | NO | RESOLVED | Implicitly covered by TestFunctionLikeMacroExpansion (finding 41) — function-like macro processing necessarily exercises `_parse_macro_arguments`. The two-arg macro test (`ADD(a, b)`) drives argument parsing. |
| 46 | `_substitute_func_macro` — NO (preprocessor.py:440) | NO | RESOLVED | Same as finding 45 — substitution is driven by function-like macro expansion tests. |
| 47 | `_eval_struct_instance` depth limit (evaluator.py:610) | NO | RESOLVED | test_hexpat_tails_wave4.py:TestEvalDepthLimit:180-220 · `pytest.raises(HexPatRuntimeError, match="maximum evaluation depth 1 exceeded")` · oracle: `#pragma eval_depth 1` and Outer containing Inner (2 levels > 1 limit) · mutation: removing depth check allows unlimited recursion |
| 48 | `_eval_placement` pattern limit (evaluator.py:910) | NO | RESOLVED | test_hexpat_tails_wave4.py:TestPatternLimitError:226-253 · `pytest.raises(HexPatRuntimeError, match="pattern limit 1 exceeded")`, also positive case: `len(results) == 2` with `display_value == "0xAA"` and `"0xBB"` · oracle: `#pragma pattern_limit N` and known data bytes |
| 49 | `compile_to_json` MOCK VIOLATION (interpreter.py:272) | WEAK (MOCK) | RESOLVED | test_hexpat_core.py:246-276 — mock.patch removed. Real source (`"enum Status : u8 { Ok = 0, Err = 1 };"`) fed to real compiler triggers real `HexPatError(match=r"no struct declaration found")`. Oracle: documented compiler rejection of enum-only source. Mutation: swallowing error returns `{}`, test fails because no exception raised. |
| 50 | `PatternRegistry.load_source` — NO (pattern_registry.py:120) | NO | RESOLVED | test_hexpat_pattern_registry.py:331-343 · asserts `"#pragma description" in loaded` and `"u32 magic @ 0;" in loaded` after writing known content to tmp file · oracle: known content string written to disk · mutation: returning empty string fails substring checks |
| 51 | CRC stdlib functions — UNKNOWN (stdlib.py:180+) | UNKNOWN | RESOLVED | test_hexpat_tails_wave4.py:TestCRCCompute (9 tests) + TestCRCBuiltinMethods (4 tests) · oracle: `binascii.crc32` (Python stdlib, independent) and documented CRC catalog check vectors (CRC-32/ISO-HDLC of `b"123456789"` == 0xCBF43926, CRC-8/SMBUS == 0xF4, CRC-16/ARC == 0xBB3D) · mutation: wrong poly or wrong reflection produces wrong check value |

---

## STILL OPEN

The following 17 findings have no real, falsifiable gate in the current tests/ tree.

| # | Operation (source:line) | Why not real | Missing assertion |
|---|---|---|---|
| 01 | `TOOL_CAPABILITY_MAP` scripting family (base.py:74-82) | Tested only via integration path; no direct map-value lookup in `TestToolCapabilityMapCompleteness` | `assert TOOL_CAPABILITY_MAP.get("execute_script") == "scripting"` (and all 9 scripting ops) in TestToolCapabilityMapCompleteness |
| 02 | `TOOL_CAPABILITY_MAP` decompilation family (base.py:62) | Same indirect-only gap | `assert TOOL_CAPABILITY_MAP.get("decompile") == "decompilation"` directly in TestToolCapabilityMapCompleteness |
| 03 | `BinaryOperationsBridge.__init__` capability values (base.py:1046-1054) | Only abstraction instantiation guard tested; no concrete-subclass capability assertion | Concrete subclass test: `assert caps.supports_static_analysis is True`, `assert caps.supports_patching is True`, `assert "pe" in caps.supported_formats`, `assert "arm64" in caps.supported_architectures` |
| 04 | `resolve()` warning log (lazy.py:60) | AttributeError exception path tested but `_logger.warning("lazy_resolve_unknown_attribute", ...)` emission never verified | Capture `lazy_resolve_unknown_attribute` log event via structlog.testing and assert level == "warning" |
| 05 | `resolve()` TypeError for non-bridge (lazy.py:68-71) | Branch `raise TypeError(...)` never executed in any test | Patch `LAZY_EXPORTS` to contain an entry resolving to a non-class attribute; assert `TypeError` with `f"lazy export ... is not a bridge or installer class"` |
| 06 | `build_schema_property` array+object recursive (schemas.py:258-267) | `_build_array_items` with `element_type == "object"` path never reached in bridge tests | `build_schema_property(ToolParameter(type="array", items_type="object", item_properties=[...]))` validated with `jsonschema.Draft7Validator` |
| 07 | `validate_tool_parameter` unrecognized items_type (schemas.py:419-422) | `ValidationError("Array parameter has unrecognized items_type …")` branch never reached | `validate_tool_parameter(ToolParameter(type="array", items_type="CustomClass"))` and assert `ValidationError` message contains `"unrecognized items_type"` |
| 08 | `validate_tool_parameter` array objects no item_properties (schemas.py:427-434) | `ValidationError("Array of objects requires item_properties …")` branch never reached | `validate_tool_parameter(ToolParameter(type="array", items_type="object", item_properties=[]))` and assert severity == "error" and message contains `"requires item_properties"` |
| 09 | `_assert_never` (schemas.py:28-48) | Architecturally unreachable: exhaustive if/elif/else in `get_schema_for_provider` prevents execution by design | Cannot be tested via production paths; would require bypassing exhaustive dispatch. No resolution path without exposing a private test-only hook. |
| 10 | `_read_exact` timeout raises ToolError (npc.py:597-605) | No test drives `_read_exact` into the timeout path in isolation | Async test with fake pipe that never delivers bytes, with `io_timeout` set small; assert `ToolError` with timeout message |
| 11 | `_cancel_io` (npc.py:869-882) | Never asserted directly; invoked internally by close/timeout but no test verifies `CancelIoEx` called or log emitted | Test that asserts `pipe_cancel_io_called` log event (or that close() completes without hang) when `_cancel_io` is invoked |
| 12 | `bridges/__init__.py __dir__` (\_\_init\_\_.py:90-96) | Never called; sorted-union logic of `__all__` + `globals()` untested | `assert set(LAZY_EXPORTS) <= set(dir(bridges_pkg))` and `assert set(__all__) <= set(dir(bridges_pkg))` |
| 13 | `HexEditorBridge.get_selection` exact tuple (hex_editor.py:5928) | `test_selection_dispatch.py:270` asserts exact `(start, end)` only on `_StubBridge`, not the real bridge; `test_bridge_concurrent.py:153` tests only `is None` case on real bridge | `_run(bridge.select_range(4, 12)); assert _run(bridge.get_selection()) == (4, 12)` on real `HexEditorBridge` with open document |
| 14 | `HexPatError.__str__` exact format (errors.py:44-45) | Only substring `"[span ...]"` checked on subclass; base class format `"file:line:col: message"` never asserted with exact equality | `assert str(HexPatError("bad type", line=3, column=7, file="test.hexpat")) == "test.hexpat:3:7: bad type"` |
| 15 | `import mod;` preprocessor directive (preprocessor.py:220) | `import std::mem;` shorthand path entirely untested | `pp.process("import std::string;\nu32 x @ 0;")` with configured include path; assert the library source is inlined |
| 16 | Circular include prevention (preprocessor.py:290) | Only `#pragma once` double-include tested; A→B→A circular include never verified to halt | Create files A including B including A; assert preprocessing completes (no infinite loop) and duplicate lines are bounded |
| 17 | `_process_defines` 64-pass limit (preprocessor.py:320) | Convergence tested; limit boundary never asserted | Self-referential macro that cannot converge; assert preprocessing halts with bounded expansion count, not an infinite loop |

---

## Summary Counts

- **Section 01** (bridge framework): 25 findings; 13 RESOLVED, 0 RED_BY_DESIGN, 12 NOT_RESOLVED
- **Section 05** (hex editor bridge): 11 findings; 10 RESOLVED, 0 RED_BY_DESIGN, 1 NOT_RESOLVED
- **Section 06** (hexpat engine): 15 findings; 11 RESOLVED, 0 RED_BY_DESIGN, 4 NOT_RESOLVED
- **TOTAL**: 51 findings; 34 RESOLVED, 0 RED_BY_DESIGN, **17 NOT_RESOLVED**
