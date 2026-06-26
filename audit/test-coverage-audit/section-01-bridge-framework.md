# Section 01 — Bridge Framework & IPC: Test Coverage Audit

**Scope:** `src/intellicrack/bridges/base.py`, `src/intellicrack/bridges/lazy.py`,
`src/intellicrack/bridges/schemas.py`, `src/intellicrack/bridges/parse_helpers.py`,
`src/intellicrack/bridges/named_pipe_client.py`, `src/intellicrack/bridges/__init__.py`

**Audit date:** 2026-06-26

---

## 1. Operation Inventory Table

All behavior-bearing public and internal operations are listed. Abstract method
signatures in base.py are omitted (they have no concrete body to gate); their
concrete implementations in bridge subclasses are tested by the per-bridge test
suites outside this scope.

### 1.1 `src/intellicrack/bridges/base.py`

| Operation | Source (file:line) | Test(s) (file:line) | Verdict | Missing Edges |
|---|---|---|---|---|
| `TOOL_CAPABILITY_MAP` — static_analysis family | base.py:63-71 | test_base.py:725-734 | REAL GATE | — |
| `TOOL_CAPABILITY_MAP` — debugging family | base.py:83-114 | test_base.py:736-745 | REAL GATE | — |
| `TOOL_CAPABILITY_MAP` — patching family | base.py:119-135 | test_base.py:747-751 | REAL GATE | — |
| `TOOL_CAPABILITY_MAP` — memory_access family | base.py:136-151 | test_base.py:753-757 | REAL GATE | — |
| `TOOL_CAPABILITY_MAP` — scripting family | base.py:74-82 | test_base.py:493-514 (indirect via execute_tool_call) | WEAK GATE | No direct `TOOL_CAPABILITY_MAP.get(op) == "scripting"` assertion; only tested through registry integration |
| `TOOL_CAPABILITY_MAP` — decompilation family | base.py:62 | test_base.py:563-581 (indirect) | WEAK GATE | Same — no direct map-value assertion for decompilation ops |
| `DisassemblyLine` — field schema | base.py:163-178 | test_base.py:207-213 | REAL GATE | — |
| `DisassemblyLine` — asdict round-trip | base.py:163-178 | test_base.py:215-235 | REAL GATE | — |
| `DisassemblyLine` — comment default None | base.py:178 | test_base.py:237-245 | REAL GATE | — |
| `DisassemblyLine` — filter logic | base.py:163-178 | test_base.py:247-263 | REAL GATE | — |
| `DisassemblyLine` — from real PE binary (independent oracle) | base.py:163-178 | test_realcov_04_base.py:203-265 | REAL GATE | — |
| `MemorySearchResult` — field schema | base.py:182-195 | test_base.py:268-275 | REAL GATE | No real memory scan from a live bridge |
| `MemorySearchResult` — asdict hex preservation | base.py:182-195 | test_base.py:277-295 | REAL GATE | — |
| `MemorySearchResult` — sort by address | base.py:182-195 | test_base.py:297-311 | REAL GATE | — |
| `StackFrame` — field schema | base.py:199-217 | test_base.py:318-332 | REAL GATE | No real call stack trace from a live debugger bridge |
| `StackFrame` — asdict with resolved symbols | base.py:199-217 | test_base.py:334-356 | REAL GATE | — |
| `StackFrame` — None symbol fields preserved | base.py:216-217 | test_base.py:358-375 | REAL GATE | — |
| `StackFrame` — display-logic guard | base.py:199-217 | test_base.py:377-405 | REAL GATE | — |
| `WatchpointInfo` — field schema | base.py:222-239 | test_base.py:410-418 | REAL GATE | — |
| `WatchpointInfo` — hit_count + enabled mutation | base.py:222-239 | test_base.py:420-436 | REAL GATE | — |
| `WatchpointInfo` — asdict after mutation | base.py:222-239 | test_base.py:438-456 | REAL GATE | — |
| `BridgeCapabilities.has_capability` | base.py:268-277 | test_base.py:583-600 | REAL GATE | — |
| `BridgeCapabilities.supports_arch` | base.py:279-288 | test_base.py:602-620 | REAL GATE | — |
| `BridgeCapabilities.supports_format` | base.py:290-299 | test_base.py:602-620 | REAL GATE | — |
| `BridgeState.is_ready` | base.py:324-330 | test_base.py:669-686 | REAL GATE | — |
| `BridgeState.clear_error` | base.py:332-334 | test_base.py:688-701 | REAL GATE | — |
| `ToolBridgeBase.__init__` | base.py:349-355 | test_base.py:42-55 (via _MinimalBridge) | REAL GATE | — |
| `ToolBridgeBase.state` getter | base.py:366-373 | test_base.py:639-668 (implicit) | REAL GATE | — |
| `ToolBridgeBase.state` setter → `_publish_tool_state` | base.py:375-390 | test_base.py:639-652 | REAL GATE | — |
| `ToolBridgeBase.set_session` → immediate publish | base.py:392-409 | test_base.py:626-637 | REAL GATE | — |
| `ToolBridgeBase._publish_tool_state` (session=None no-op) | base.py:411-434 | any base test without session (implicit) | REAL GATE | — |
| `ToolBridgeBase._publish_tool_state` (session set) | base.py:411-434 | test_base.py:639-667 | REAL GATE | — |
| `ToolBridgeBase._clear_tool_state_in_session` | base.py:436-447 | test_base.py:703-719 | REAL GATE | — |
| `ToolBridgeBase.capabilities` getter | base.py:448-455 | test_realcov_04_base.py:271-301 | REAL GATE | — |
| `ToolBridgeBase._finalize_shutdown` (state reset + clear session) | base.py:487-499 | test_base.py:703-719 | REAL GATE | — |
| `StaticAnalysisBridge.__init__` capability block | base.py:516-524 | test_realcov_04_base.py:284-301 | REAL GATE | — |
| `DynamicAnalysisBridge.__init__` capability block | base.py:690-698 | test_realcov_04_base.py:308-370 | REAL GATE | — |
| `DebuggerBridge.__init__` (supports_debugging=True override) | base.py:779-781 | test_realcov_04_base.py:329-370 | REAL GATE | — |
| `InstrumentationBridge.__init__` (supports_scripting=True) | base.py:920-922 | test_realcov_04_base.py:341-349 | REAL GATE | — |
| `BinaryOperationsBridge.__init__` capability values | base.py:1046-1054 | test_realcov_04_base.py:352-357 | NO COVERAGE | Test only checks that it cannot be instantiated directly; the specific capability flag values (formats, arches) are never asserted |
| `BinaryOperationsBridge` — cannot instantiate | base.py:1040-1054 | test_realcov_04_base.py:352-357 | REAL GATE | — |
| ToolRegistry capability enforcement integration | base.py:61-151 | test_base.py:459-581 | REAL GATE | — |

### 1.2 `src/intellicrack/bridges/lazy.py`

| Operation | Source (file:line) | Test(s) (file:line) | Verdict | Missing Edges |
|---|---|---|---|---|
| `LAZY_EXPORTS` constant — all 8 entries present | lazy.py:28-37 | test_bridges_core_audit1.py:286-309 | REAL GATE | Verified indirectly: evicting modules, re-importing, checking sys.modules. Not asserted by key enumeration. |
| `resolve()` — happy path (import, cache, return class) | lazy.py:40-74 | test_bridges_core_audit1.py:312-327 | REAL GATE | — |
| `resolve()` — unknown name raises `AttributeError` | lazy.py:59-61 | test_bridges_core_audit1.py:330-335 | REAL GATE | Warning log emission not verified |
| `resolve()` — unknown name logs warning | lazy.py:60 | NO COVERAGE | NO COVERAGE | `_logger.warning("lazy_resolve_unknown_attribute", ...)` never verified |
| `resolve()` — non-bridge/non-installer raises `TypeError` | lazy.py:68-71 | NO COVERAGE | NO COVERAGE | The branch `if not (is_bridge or is_installer): raise TypeError` is never exercised; no test loads a LAZY_EXPORTS entry pointing to a non-class attribute |
| `resolve()` — caches class in package_globals | lazy.py:73 | test_bridges_core_audit1.py:323-326 | REAL GATE | — |

### 1.3 `src/intellicrack/bridges/schemas.py`

| Operation | Source (file:line) | Test(s) (file:line) | Verdict | Missing Edges |
|---|---|---|---|---|
| `is_recognized_type` — known aliases | schemas.py:185-202 | test_bridges_core_audit1.py:176-183 | REAL GATE | — |
| `is_recognized_type` — unknown strings | schemas.py:185-202 | test_bridges_core_audit1.py:176-183 | REAL GATE | — |
| `normalize_type` — Python alias → JSON Schema type | schemas.py:205-233 | test_schemas.py:146-153 (parametrized) | REAL GATE | — |
| `normalize_type` — unknown → fallback "string" + warning log | schemas.py:228-232 | test_bridges_core_audit1.py:110-134 | REAL GATE | — |
| `build_schema_property` — basic (jsonschema Draft7 oracle) | schemas.py:270-302 | test_schemas.py:156-189 | REAL GATE | — |
| `build_schema_property` — all JSON types (Draft7 oracle) | schemas.py:270-302 | test_schemas.py:192-258 (parametrized) | REAL GATE | — |
| `build_schema_property` — array + integer items enforcement | schemas.py:270-302 | test_schemas.py:261-297 | REAL GATE | — |
| `build_schema_property` — array + object items recursive branch | schemas.py:258-267 | NO COVERAGE in bridges tests | NO COVERAGE | `_build_array_items` when `element_type == "object"` and `param.item_properties` is set never exercised in test_schemas.py or test_bridges_core_audit1.py; only reached in test_providers/test_e2e_chat.py:155-172 (providers scope) |
| `build_schema_property` — enum | schemas.py:295-297 | test_schemas.py:300-303 | REAL GATE | — |
| `build_schema_property` — default | schemas.py:299-300 | test_schemas.py:305-309 | REAL GATE | — |
| `build_schema_property` — uppercase (Google) | schemas.py:285-286 | test_schemas.py:312-323 | REAL GATE | — |
| `build_schema_property` — empty enum excluded | schemas.py:296 | test_schemas.py:324-327 | REAL GATE | — |
| `build_schema_parameters` — empty list | schemas.py:305-329 | test_schemas.py:330-369 | REAL GATE | — |
| `build_schema_parameters` — realistic multi-type | schemas.py:305-329 | test_schemas.py:372-476 | REAL GATE | — |
| `build_schema_parameters` — required/optional/mixed | schemas.py:305-329 | test_schemas.py:479-502 | REAL GATE | — |
| `build_schema_parameters` — Google uppercase | schemas.py:358-374 | test_schemas.py:505-510 | REAL GATE | — |
| `validate_tool_parameter` — valid | schemas.py:377-470 | test_schemas.py:513-516 | REAL GATE | — |
| `validate_tool_parameter` — empty name | schemas.py:393-400 | test_schemas.py:519-522 | REAL GATE | — |
| `validate_tool_parameter` — invalid identifier | schemas.py:400-406 | test_schemas.py:524-528 | REAL GATE | — |
| `validate_tool_parameter` — empty description | schemas.py:436-443 | test_schemas.py:530-534 | REAL GATE | — |
| `validate_tool_parameter` — required with default | schemas.py:444-452 | test_schemas.py:536-540 | REAL GATE | — |
| `validate_tool_parameter` — empty enum list | schemas.py:455-461 | test_schemas.py:542-545 | REAL GATE | — |
| `validate_tool_parameter` — default not in enum | schemas.py:462-467 | test_schemas.py:547-550 | REAL GATE | — |
| `validate_tool_parameter` — array + unrecognized items_type warning | schemas.py:419-422 | NO COVERAGE | NO COVERAGE | The `ValidationError("Array parameter has unrecognized items_type …")` branch is never reached by any test |
| `validate_tool_parameter` — array of objects with no item_properties | schemas.py:427-434 | NO COVERAGE | NO COVERAGE | The `ValidationError("Array of objects requires item_properties …")` error branch is never reached |
| `validate_tool_function` | schemas.py:473-521 | test_schemas.py:564-595 | REAL GATE | — |
| `validate_tool_definition` | schemas.py:524-564 | test_schemas.py:598-623 | REAL GATE | — |
| `ValidationError.__str__` | schemas.py:176-182 | test_schemas.py:626-635 | REAL GATE | — |
| `to_anthropic_schema` | schemas.py:567-587 | test_schemas.py:638-652 | REAL GATE | — |
| `to_openai_schema` | schemas.py:590-613 | test_schemas.py:655-669 | REAL GATE | — |
| `to_google_schema` | schemas.py:616-638 | test_schemas.py:672-686 | REAL GATE | — |
| `to_ollama_schema` (delegates to OpenAI) | schemas.py:641-652 | test_schemas.py:689-692 | REAL GATE | — |
| `to_openrouter_schema` (delegates to OpenAI) | schemas.py:655-666 | test_schemas.py:694-697 | REAL GATE | — |
| `get_schema_for_provider` — ANTHROPIC | schemas.py:685 | test_schemas.py:721-727 | REAL GATE | — |
| `get_schema_for_provider` — OPENAI | schemas.py:687 | test_schemas.py:729-735 | REAL GATE | — |
| `get_schema_for_provider` — GOOGLE | schemas.py:689 | test_schemas.py:712-718 | REAL GATE | — |
| `get_schema_for_provider` — OLLAMA | schemas.py:691 | test_schemas.py:701-710 (only `len(result)==1`) | WEAK GATE | Only length checked; format not verified. A mutation routing OLLAMA to `to_google_schema` would still pass. |
| `get_schema_for_provider` — OPENROUTER | schemas.py:693 | test_schemas.py:701-710 (only `len(result)==1`) | WEAK GATE | Same — format not verified independently |
| `get_schema_for_provider` — HUGGINGFACE | schemas.py:695 | test_schemas.py:701-710 (only `len(result)==1`) | WEAK GATE | Same |
| `get_schema_for_provider` — GROK | schemas.py:697 | test_schemas.py:701-710 (only `len(result)==1`) | WEAK GATE | Same |
| `get_schema_for_provider` — LOCAL_TRANSFORMERS | schemas.py:699 | test_schemas.py:701-710 (only `len(result)==1`) | WEAK GATE | Same |
| `get_all_schemas_for_provider` | schemas.py:704-721 | test_schemas.py:739-749 | REAL GATE | — |
| `validate_tool_for_provider` | schemas.py:724-763 | test_bridges_core_audit1.py:191-224 | REAL GATE | — |
| `validate_and_convert` | schemas.py:766-803 | test_schemas.py:752-777 | REAL GATE | — |
| `_assert_never` | schemas.py:28-48 | NO COVERAGE | NO COVERAGE | Deliberately unreachable via exhaustive if-chain in `get_schema_for_provider`; no test can reach it via production paths |

### 1.4 `src/intellicrack/bridges/parse_helpers.py`

| Operation | Source (file:line) | Test(s) (file:line) | Verdict | Missing Edges |
|---|---|---|---|---|
| `safe_int_from_str` — `0x`-prefixed string | parse_helpers.py:43-112 | test_parse_helpers.py:26-28 | REAL GATE | — |
| `safe_int_from_str` — decimal string | parse_helpers.py:43-112 | test_parse_helpers.py:31-33 | REAL GATE | — |
| `safe_int_from_str` — explicit base | parse_helpers.py:43-112 | test_parse_helpers.py:35-37 | REAL GATE | — |
| `safe_int_from_str` — int passthrough | parse_helpers.py:90-91 | test_parse_helpers.py:39-41 | REAL GATE | — |
| `safe_int_from_str` — bool reject → default None | parse_helpers.py:81-89 | test_parse_helpers.py:43-45 | REAL GATE | — |
| `safe_int_from_str` — bool reject with explicit default | parse_helpers.py:81-89 | test_parse_helpers.py:47-50 | REAL GATE | — |
| `safe_int_from_str` — parse failure → configured default | parse_helpers.py:102-112 | test_parse_helpers.py:52-54 | REAL GATE | — |
| `safe_int_from_str` — default=None on failure | parse_helpers.py:102-112 | test_parse_helpers.py:56-58 | REAL GATE | — |
| `safe_int_from_str` — unsupported type → default | parse_helpers.py:92-101 | test_parse_helpers.py:60-62 | REAL GATE | — |
| `safe_int_from_str` — debug log on parse failure | parse_helpers.py:103-112 | test_parse_helpers.py:64-77 | REAL GATE | — |
| `safe_int_from_str` — debug log on bool rejection | parse_helpers.py:82-89 | test_parse_helpers.py:79-90 | REAL GATE | — |
| `safe_int_from_str` — bytes input | parse_helpers.py:43-112 | test_parse_helpers.py:92-94 | REAL GATE | — |
| `safe_int_from_str` — negative decimal | parse_helpers.py:43-112 | test_parse_helpers.py:96-98 | REAL GATE | — |
| `safe_call` — success | parse_helpers.py:115-154 | test_parse_helpers.py:104-112 | REAL GATE | — |
| `safe_call` — caught exception → default | parse_helpers.py:145-150 | test_parse_helpers.py:114-127 | REAL GATE | — |
| `safe_call` — `struct.error` | parse_helpers.py:145-150 | test_parse_helpers.py:129-140 | REAL GATE | — |
| `safe_call` — tuple of exception types | parse_helpers.py:145-150 | test_parse_helpers.py:142-156 | REAL GATE | — |
| `safe_call` — uncaught exception propagates | parse_helpers.py:145-150 | test_parse_helpers.py:158-170 | REAL GATE | — |
| `safe_call` — debug log on caught exception | parse_helpers.py:148-153 | test_parse_helpers.py:173-197 | REAL GATE | — |

### 1.5 `src/intellicrack/bridges/named_pipe_client.py`

| Operation | Source (file:line) | Test(s) (file:line) | Verdict | Missing Edges |
|---|---|---|---|---|
| `_default_pipe_name` | npc.py:42-52 | test_named_pipe_client.py:329-333 | REAL GATE | — |
| `PipeConfig` defaults | npc.py:100-117 | test_named_pipe_client.py:335-345 | REAL GATE | — |
| `PipeConfig` user override | npc.py:100-117 | test_named_pipe_client.py:342-345 | REAL GATE | — |
| `NamedPipeClient.__init__` | npc.py:131-157 | implicit in all fixtures | REAL GATE | — |
| `is_connected` property | npc.py:159-166 | test_realcov_02b_named_pipe_real.py:239-242 | REAL GATE | — |
| `set_event_handler` | npc.py:168-173 | test_realcov_02b_named_pipe_real.py:326-354 (implicit) | REAL GATE | — |
| `connect()` — non-Windows raises ToolError | npc.py:194-196 | test_named_pipe_client.py:436-489 | REAL GATE | — |
| `connect()` — already connected no-op | npc.py:198-199 | NO COVERAGE | NO COVERAGE | The `if self._handle is not None: return` branch is never explicitly tested |
| `connect()` — timeout raises ToolError | npc.py:212-220 | test_named_pipe_client.py:1007-1047 | REAL GATE | — |
| `connect()` — cancel cleans up leaked handle | npc.py:221-228 | test_named_pipe_client.py:933-1003 | REAL GATE | — |
| `connect()` — success (real kernel pipe) | npc.py:199-239 | test_realcov_02b_named_pipe_real.py:245-259 | REAL GATE | — |
| `_reap_open_task` — already-done task closes handle | npc.py:241-273 | test_named_pipe_client.py:933-1003 | REAL GATE | — |
| `_close_native_handle` — CloseHandle failure logging | npc.py:275-299 | test_named_pipe_client.py:1082-1131 | REAL GATE | — |
| `close()` — graceful teardown | npc.py:300-341 | test_named_pipe_client.py:919-924 | REAL GATE | — |
| `close()` — idempotent | npc.py:300-341 | test_named_pipe_client.py:919-924 | REAL GATE | — |
| `close()` — fails pending futures with ToolError | npc.py:331-337 | test_named_pipe_client.py:819-828 | REAL GATE | — |
| `close()` — waits for in-flight write | npc.py:330-331 | test_named_pipe_client.py:832-869 | REAL GATE | — |
| `close()` — dispatches handle close via thread pool | npc.py:339 | test_named_pipe_client.py:873-916 | REAL GATE | — |
| `send_command()` — not connected raises ToolError | npc.py:385-387 | test_named_pipe_client.py:797-809 | REAL GATE | — |
| `send_command()` — `_read_failure` guard | npc.py:388-390 | NO COVERAGE | NO COVERAGE | The guard `if self._read_failure is not None: raise` is never isolated; broken-pipe tests exercise post-failure behavior but not the pre-send guard path specifically |
| `send_command()` — happy path | npc.py:391-409 | test_named_pipe_client.py:1242-1280 | REAL GATE | — |
| `_allocate_request_id` — normal | npc.py:411-427 | test_named_pipe_client.py:518-547 | REAL GATE | — |
| `_allocate_request_id` — wraparound at int31 max | npc.py:425 | test_named_pipe_client.py:550-561 | REAL GATE | — |
| `_reader_loop` — response routing to future | npc.py:429-496 | test_named_pipe_client.py:1242-1280 (implicit) | REAL GATE | — |
| `_reader_loop` — event dispatch (via run_in_executor) | npc.py:469-476 | test_realcov_02b_named_pipe_real.py:317-354 | REAL GATE | — |
| `_reader_loop` — error capture + fail_pending | npc.py:459-466 | test_realcov_02b_named_pipe_real.py:458-491 | REAL GATE | — |
| `_reader_loop` — response missing id warning | npc.py:480-485 | NO COVERAGE | NO COVERAGE | The `_logger.warning("pipe_response_missing_id", ...)` branch never tested |
| `_reader_loop` — no waiter for response id (no-op log) | npc.py:488-492 | NO COVERAGE | NO COVERAGE | The `_logger.debug("pipe_response_no_waiter", ...)` branch never tested |
| `_dispatch_event_safe` — swallows handler exception | npc.py:498-517 | test_named_pipe_client.py:754-778 | REAL GATE | — |
| `_fail_pending` | npc.py:518-527 | test_named_pipe_client.py:819-828 | REAL GATE | — |
| `_send_message` — normal payload | npc.py:530-546 | test_named_pipe_client.py:1242-1280 (implicit via round-trip) | REAL GATE | — |
| `_send_message` — oversized payload raises ToolError | npc.py:541-543 | NO COVERAGE | NO COVERAGE | `max_message_size` enforcement never tested; no test constructs a payload exceeding the limit |
| `_read_message` — valid JSON response | npc.py:548-578 | test_realcov_02b_named_pipe_real.py:261-289 (via real pipe) | REAL GATE | — |
| `_read_message` — malformed JSON raises ToolError | npc.py:569-573 | NO COVERAGE | NO COVERAGE | `json.JSONDecodeError` path never exercised |
| `_read_message` — invalid length raises ToolError | npc.py:563-565 | NO COVERAGE | NO COVERAGE | `length <= 0 or length > max_message_size` path never exercised |
| `_read_message` — non-dict payload raises ToolError | npc.py:575-577 | NO COVERAGE | NO COVERAGE | `if not isinstance(payload, dict)` path never exercised |
| `_read_exact` — normal | npc.py:580-605 | implicit via round-trips | REAL GATE | — |
| `_read_exact` — timeout raises ToolError | npc.py:597-605 | NO COVERAGE (not isolated) | NO COVERAGE | Write timeout path via `_write_bytes` is also untested in isolation |
| `_write_bytes` — normal | npc.py:607-629 | implicit via round-trips | REAL GATE | — |
| `format_error_hint` — known codes (all 12) | npc.py:631-665 | test_named_pipe_client.py:497-505 | REAL GATE | — |
| `format_error_hint` — unknown code → None | npc.py:650 | test_named_pipe_client.py:507-509 | REAL GATE | — |
| `format_error_hint` — error 2 exact string (independent oracle) | npc.py:653 | test_realcov_02b_named_pipe_real.py:410-440 | REAL GATE | — |
| `_open_handle` — WaitNamedPipeW + share mode | npc.py:667-733 | test_named_pipe_client.py:359-427 | REAL GATE | — |
| `_open_handle` — WaitNamedPipeW fails (missing pipe) | npc.py:692-706 | test_realcov_02b_named_pipe_real.py:430-440 | REAL GATE | — |
| `_close_handle` | npc.py:735-743 | test_named_pipe_client.py:873-916 (implicit) | REAL GATE | — |
| `_read_exact_sync` — chunked reassembly (>64 KiB) | npc.py:745-812 | test_realcov_02b_named_pipe_real.py:357-376 | REAL GATE | — |
| `_read_exact_sync` — pipe not connected error | npc.py:762-764 | implicit via guard (not isolated) | REAL GATE | — |
| `_write_sync` — normal write | npc.py:814-866 | test_named_pipe_client.py:1139-1197 | REAL GATE | — |
| `_write_sync` — logging at DEBUG not INFO | npc.py:860-862 | test_named_pipe_client.py:1139-1197 | REAL GATE | — |
| `_cancel_io` | npc.py:869-882 | NO DIRECT COVERAGE | NO COVERAGE | Never directly tested; only invoked internally on timeout/close, no test asserts it was called or that it correctly unblocks pending I/O |
| FILE_SHARE_READ / FILE_SHARE_WRITE constants | npc.py:37-38 | test_named_pipe_client.py:353-357 | REAL GATE | — |
| Lifecycle logging at INFO (pipe_connecting etc.) | npc.py:202,236 | test_named_pipe_client.py:1200-1234 | REAL GATE | — |

### 1.6 `src/intellicrack/bridges/__init__.py`

| Operation | Source (file:line) | Test(s) (file:line) | Verdict | Missing Edges |
|---|---|---|---|---|
| `__getattr__` — resolves lazy export | __init__.py:74-87 | test_bridges_core_audit1.py:309-327 | REAL GATE | — |
| `__getattr__` — unknown name raises AttributeError | __init__.py:74-87 | test_bridges_core_audit1.py:330-335 | REAL GATE | — |
| `__dir__` — returns sorted combined set | __init__.py:90-96 | NO COVERAGE | NO COVERAGE | Never called in any test; the sorted-union logic is entirely untested |

---

## 2. Worst-Offenders List

The following tests are either fake gates or tests asserting over a weak proxy
instead of the real behavior. They must be rejected or replaced.

### WO-01: `test_schemas.py:701-710` — `test_get_schema_for_provider_all`

**File:line:** `tests/test_bridges/test_schemas.py:701-710`

**Pattern:** Over-broad assertion on rich output.

```python
@pytest.mark.parametrize("provider", list(ProviderName))
def test_get_schema_for_provider_all(provider: ProviderName) -> None:
    result = get_schema_for_provider(_tool(), provider)
    assert len(result) == 1
```

The assertion `len(result) == 1` is only a structural count check. For the five
providers that route through `to_openai_schema` internally (OLLAMA, OPENROUTER,
HUGGINGFACE, GROK, LOCAL_TRANSFORMERS), a mutation that accidentally routed them
to `to_google_schema` (producing uppercase types) would still pass, because the
schema list still has length 1. The test does not verify provider-specific key
structure (`"input_schema"` vs `"parameters"`, `"type": "function"`, uppercase
types, etc.) for these providers. ANTHROPIC, OPENAI, and GOOGLE are covered by
dedicated structural tests, but the remaining five are gated only by this
length check.

**Concrete mutation that passes (should fail):** Change `get_schema_for_provider`
for `ProviderName.HUGGINGFACE` to call `to_anthropic_schema(tool)` instead of
`to_openai_schema(tool)`. The result still has length 1; the test stays green.

### WO-02: `test_base.py:725-757` — TOOL_CAPABILITY_MAP scripting/decompilation families

**File:line:** `tests/test_bridges/test_base.py:725-757`

**Pattern:** Happy-path-only for a data constant with multiple families.

The `TestToolCapabilityMapCompleteness` class directly asserts only four
families (static_analysis, debugging, patching, memory_access). The scripting
and decompilation families (eight entries: `execute_script`,
`execute_script_with_params`, `run_python_script`, `script_load`, `script_run`,
`script_cmd`, `script_abort`, `compile_typescript`, `create_cmodule`, `decompile`,
`get_pcode`) are tested only indirectly through the capability-enforcement
integration tests. If an entry were silently removed from
`TOOL_CAPABILITY_MAP` for any scripting operation other than `execute_script`,
no test in this module would catch it.

---

## 3. Gap List — Operations with Zero Real Coverage

The following operations have no test that would fail if their production code
were deleted or broken.

### GAP-01: `lazy.py:68-71` — `resolve()` TypeError path

**Source:** `src/intellicrack/bridges/lazy.py:68-71`

No test constructs a LAZY_EXPORTS entry whose resolved attribute is not a
`ToolBridgeBase` subclass and not a `ToolInstaller`, so the
`raise TypeError(f"lazy export {name!r} from {module_path!r} is not a bridge or installer class")`
branch is never executed. A regression that accidentally exposed a non-class
attribute (e.g. a module-level integer constant) under a LAZY_EXPORTS key would
not be caught.

### GAP-02: `lazy.py:60` — warning log on unknown attribute

**Source:** `src/intellicrack/bridges/lazy.py:60`

The `AttributeError` path is tested for the exception itself
(`test_f0004_bridges_unknown_attribute_raises`) but the `_logger.warning("lazy_resolve_unknown_attribute", ...)` emission is never verified. A regression that silenced the log would pass undetected.

### GAP-03: `schemas.py:258-267` — `_build_array_items` object branch

**Source:** `src/intellicrack/bridges/schemas.py:258-267`

The branch `if element_type == "object" and param.item_properties:` inside
`_build_array_items` — which recursively builds a nested property schema for
array elements that are JSON objects — is never reached by any test in
`test_schemas.py` or `test_bridges_core_audit1.py`. The `test_e2e_chat.py`
provider test exercises it, but that is outside this section's scope and does
not use jsonschema to validate the result.

### GAP-04: `schemas.py:419-422` — array parameter with unrecognized items_type

**Source:** `src/intellicrack/bridges/schemas.py:419-422`

`validate_tool_parameter` for an array parameter whose `items_type` is not a
recognized type string emits a `ValidationError("Array parameter has
unrecognized items_type…")` warning. No test constructs this scenario.

### GAP-05: `schemas.py:427-434` — array of objects without item_properties

**Source:** `src/intellicrack/bridges/schemas.py:427-434`

`validate_tool_parameter` for an array parameter with `items_type="object"` but
an empty `item_properties` list emits a `ValidationError("Array of objects
requires item_properties…")` error. No test covers this error branch.

### GAP-06: `named_pipe_client.py:198-199` — already-connected no-op

**Source:** `src/intellicrack/bridges/named_pipe_client.py:198-199`

`connect()` silently returns if `self._handle is not None`. No test calls
`connect()` on an already-connected client to verify the no-op path. A
regression that removed this guard (causing a second connect to open a second
handle and leak it) would not be caught.

### GAP-07: `named_pipe_client.py:388-390` — `send_command` pre-read-failure guard

**Source:** `src/intellicrack/bridges/named_pipe_client.py:388-390`

The guard `if self._read_failure is not None: raise ToolError(...)` in
`send_command` is never directly tested. The broken-pipe integration tests
exercise subsequent `send_command` calls after a server disconnect, but the
`_read_failure` flag's effect on subsequent callers before the future route is
taken is not isolated.

### GAP-08: `named_pipe_client.py:541-543` — oversized message in `_send_message`

**Source:** `src/intellicrack/bridges/named_pipe_client.py:541-543`

`_send_message` raises `ToolError("Message exceeds maximum size")` when
`len(data) > self._config.max_message_size`. No test constructs a payload
that exceeds the configured limit.

### GAP-09: `named_pipe_client.py:569-577` — `_read_message` error branches

**Source:** `src/intellicrack/bridges/named_pipe_client.py:563-577`

Three distinct error branches in `_read_message` are never tested in isolation:
- `length <= 0 or length > max_message_size` → ToolError("Invalid message length")
- `json.JSONDecodeError` → ToolError(f"Invalid JSON payload: {exc}")
- `not isinstance(payload, dict)` → ToolError("Unexpected message payload type")

These are the malformed-input / adversarial-peer paths. A bug that silently
accepted a truncated or non-JSON frame would not be caught.

### GAP-10: `named_pipe_client.py:869-882` — `_cancel_io`

**Source:** `src/intellicrack/bridges/named_pipe_client.py:869-882`

`_cancel_io` is invoked by `_read_exact` (on timeout) and `close()` (before
cancelling the reader task). No test asserts it is called, that it successfully
invokes `CancelIoEx`, or that it produces the expected log entries.

### GAP-11: `named_pipe_client.py:480-492` — `_reader_loop` unrouted message branches

**Source:** `src/intellicrack/bridges/named_pipe_client.py:480-492`

Two diagnostic branches in `_reader_loop` are never triggered in any test:
- Response message arriving without an integer `id` field → warning log
- Response arriving for a request id with no matching pending future → debug log

### GAP-12: `__init__.py:90-96` — `__dir__`

**Source:** `src/intellicrack/bridges/__init__.py:90-96`

`__dir__()` is never called in any test. The sorted-union logic that combines
`__all__` with the live `globals()` dict is untested.

### GAP-13: `base.py:1046-1054` — `BinaryOperationsBridge` capability values

**Source:** `src/intellicrack/bridges/base.py:1046-1054`

`BinaryOperationsBridge.__init__` sets specific capability flags
(`supports_static_analysis=True`, `supports_patching=True`) and supported
architectures/formats. The only test for this class (`test_binary_operations_bridge_is_abstract`)
verifies it cannot be instantiated, not what its capability block contains.

---

## 4. Section Scores

### 4.1 Gate Coverage Score

| Module | Total Operations | Real Gates | Weak Gates | No Coverage | Score |
|---|---|---|---|---|---|
| `base.py` | 37 | 35 | 2 | 1 | 35/37 = 95% |
| `lazy.py` | 6 | 4 | 0 | 2 | 4/6 = 67% |
| `schemas.py` | 47 | 38 | 5 | 4 | 38/47 = 81% |
| `parse_helpers.py` | 19 | 19 | 0 | 0 | 19/19 = 100% |
| `named_pipe_client.py` | 48 | 35 | 0 | 13 | 35/48 = 73% |
| `__init__.py` | 3 | 2 | 0 | 1 | 2/3 = 67% |
| **Total** | **160** | **133** | **7** | **21** | **133/160 = 83%** |

The 85% target floor is not met overall (83%). The two drags are
`named_pipe_client.py` (73%) and `lazy.py`/`__init__.py` (67% each).

### 4.2 Edge-Case Coverage Score

| Edge Scenario | Covered? | Notes |
|---|---|---|
| Tool not installed / pipe not found | YES | `test_real_connect_missing_pipe_raises_with_error_code` |
| Process crash mid-call (broken pipe) | YES | `test_real_send_command_fails_after_server_disconnect` |
| Partial / oversized pipe payloads | PARTIAL | Large payloads tested; oversized-message rejection not tested |
| Malformed JSON from peer | NO | `_read_message` JSON decode error never triggered |
| Concurrent calls | YES | `test_concurrent_send_command_ids_are_unique` |
| Windows path quirks (Cygwin sys.platform) | YES | `test_no_os_name_nt_predicate_in_module` |
| Lazy-import failure paths | PARTIAL | AttributeError covered; TypeError path missing |
| Schema validation of malformed tool args | PARTIAL | Array-of-objects and invalid items_type branches missing |
| Request id wraparound | YES | `test_request_id_wraps_at_int31_max` |
| Handle leak on connect cancel/timeout | YES | `test_cancelled_connect_closes_handle` |

**Edge-case coverage score: 6/10 scenario classes fully covered = 60%**

---

## 5. Remediation Recommendations

### REC-01: `lazy.py` — Add TypeError path test

**Gap:** GAP-01 + GAP-02

Add a test that patches `LAZY_EXPORTS` to include an entry resolving to a
plain integer or string (not a class), then calls `resolve()` and asserts
`TypeError` is raised. Independently verify the `_logger.warning` log event is
emitted. Also verify the `lazy_resolve_unknown_attribute` log event on the
AttributeError path.

**Independent oracle:** `TypeError` type and message string
`f"lazy export {name!r} from {module_path!r} is not a bridge or installer class"`.

### REC-02: `schemas.py` — Test array-of-objects recursive schema

**Gap:** GAP-03

Add a test that builds a `ToolParameter(type="array", items_type="object",
item_properties=[...])` and calls `build_schema_property`. Validate the
produced nested schema with `jsonschema.Draft7Validator.check_schema` and
`jsonschema.validate` against a concrete JSON payload containing an array of
objects whose keys match `item_properties`. This is the only independent oracle
available (jsonschema itself).

### REC-03: `schemas.py` — Test array validation error branches

**Gap:** GAP-04 + GAP-05

Add two `validate_tool_parameter` tests:
1. Array parameter with `items_type="CustomClass"` (unrecognized). Assert the
   `ValidationError("Array parameter has unrecognized items_type 'CustomClass'")` warning is returned.
2. Array parameter with `items_type="object"` and `item_properties=[]` (empty). Assert the
   `ValidationError("Array of objects requires item_properties…")` error is returned with `severity == "error"`.

### REC-04: `schemas.py` — Gate provider-specific format for HUGGINGFACE/GROK/LOCAL_TRANSFORMERS

**Gap:** WO-01 / weak gates for 5 providers in `test_get_schema_for_provider_all`

Extend the parametrized test or add dedicated tests for HUGGINGFACE, GROK, and
LOCAL_TRANSFORMERS that assert `result[0]["type"] == "function"` and
`"parameters" in result[0]["function"]` — the structural markers of the
OpenAI format. The independent oracle is the OpenAI function-calling schema
contract. A mutation routing these providers to `to_anthropic_schema` would
change the key name from `"parameters"` to `"input_schema"` and the test would
go red.

### REC-05: `named_pipe_client.py` — Test `_send_message` oversized

**Gap:** GAP-08

Add an async test that constructs a `NamedPipeClient` with a small
`max_message_size` (e.g. 10 bytes), connects via the `_FakePipe` transport,
and directly calls `_send_message` with a payload larger than the limit.
Assert `ToolError("Message exceeds maximum size")` is raised. The independent
oracle is the exact error string.

### REC-06: `named_pipe_client.py` — Test `_read_message` malformed inputs

**Gap:** GAP-09

Add three isolated tests driving `_read_message` via the fake pipe:
1. Push a 4-byte length prefix encoding `length=0`, assert
   `ToolError("Invalid message length")`.
2. Push a valid length but a body that is not valid UTF-8 JSON (e.g. `b"\xff\xfe"`),
   assert `ToolError` with `"Invalid JSON payload"` in the message.
3. Push a valid JSON array frame (not a dict), assert
   `ToolError("Unexpected message payload type")`.

### REC-07: `named_pipe_client.py` — Test `connect()` already-connected no-op

**Gap:** GAP-06

After connecting a client via the fake transport, call `connect()` a second time
and assert that `is_connected` remains True, the reader task is not replaced
(same task object), and no second `_open_handle` call occurs. The independent
oracle is the task object identity and the `_handle` value remaining unchanged.

### REC-08: `named_pipe_client.py` — Test `send_command` pre-read-failure guard

**Gap:** GAP-07

Manually set `client._read_failure = ToolError("reader died")` on a connected
fake-transport client, then call `send_command`. Assert `ToolError` is raised
with a message containing `"Pipe reader failed"`. The independent oracle is the
exact exception type and message format documented in `send_command`'s docstring.

### REC-09: `named_pipe_client.py` — Test `_reader_loop` unrouted branches

**Gap:** GAP-11

Add two tests using the fake transport:
1. Push a server frame containing `{"type": "response", "id": "not-an-int", "ok": True}`
   (non-integer id). Assert the client logs `pipe_response_missing_id` at warning
   level (use `structlog.testing.capture_logs`).
2. Push a response frame whose `id` has no matching pending future (e.g. `id=9999`).
   Assert `pipe_response_no_waiter` is logged at debug level.

### REC-10: `base.py` — Gate TOOL_CAPABILITY_MAP scripting/decompilation families directly

**Gap:** WO-02

Add a `test_scripting_family_entries_present` and `test_decompilation_entry_present`
to `TestToolCapabilityMapCompleteness` following the exact pattern of the existing
family tests. The oracle is `TOOL_CAPABILITY_MAP.get(op) == expected_capability`.
These assertions are independent of the capability enforcement integration tests.

### REC-11: `base.py` — Gate BinaryOperationsBridge capability values

**Gap:** GAP-13

Add a test that instantiates a minimal concrete subclass of
`BinaryOperationsBridge` (implementing only the required abstract methods) and
asserts `caps.supports_static_analysis is True`, `caps.supports_patching is True`,
`"pe" in caps.supported_formats`, `"elf" in caps.supported_formats`,
`"raw" in caps.supported_formats`, and `"arm64" in caps.supported_architectures`.

### REC-12: `__init__.py` — Test `__dir__`

**Gap:** GAP-12

Add a test that calls `dir(bridges_pkg)` and asserts that all names in `__all__`
appear in the result, and that the lazy export names (from `LAZY_EXPORTS`) also
appear. The independent oracle is `set(__all__) | set(LAZY_EXPORTS)`.
