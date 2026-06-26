# Section 7 — Core Orchestration, Session & Context: Test Coverage Audit

**Audit date:** 2026-06-26
**Auditor:** test-reviewer agent
**Scope:** `src/intellicrack/core/orchestrator.py`, `session.py`, `process_manager.py`,
`analysis_aggregator.py`, `transform_pipeline.py`, `tools.py`

---

## 1. Source Inventory

Six source files, enumerated by class/function bearing public-facing behavior.

| # | Operation | Source file:line | Description |
|---|-----------|-----------------|-------------|
| 1 | `OrchestratorConfig` defaults | orchestrator.py ~90 | Dataclass with confirmation_level, max_iterations, timeout_seconds, stream_responses, stream_mode |
| 2 | `OrchestratorStats.record_response_time` | orchestrator.py ~140 | Rolling average of LLM response times |
| 3 | `OrchestratorStats.to_dict` | orchestrator.py ~155 | Serializes all 10 stats fields |
| 4 | `BRIDGE_DESTRUCTIVE_METHODS` | orchestrator.py ~45 | Dict mapping ToolName → frozenset of destructive method names, 7 entries |
| 5 | `classify_tool_call(call)` | orchestrator.py ~200 | Returns "read_only", "destructive", or "unknown"; exact-match lookup |
| 6 | `is_destructive_operation(call)` | orchestrator.py ~220 | Returns True for unknown bridge (fail-safe) |
| 7 | `_split_tool_function_name(call)` | orchestrator.py ~230 | Handles "tool.method" and bare "method" form |
| 8 | `extract_imports(binary)` | orchestrator.py ~250 | Extracts ImportInfo list from lief PE/ELF/MachO |
| 9 | `extract_exports(binary)` | orchestrator.py ~290 | Extracts ExportInfo list from lief PE/ELF/MachO |
| 10 | `_parse_binary_with_lief(path)` | orchestrator.py ~330 | Parses binary file; returns lief binary object |
| 11 | `estimate_tokens(text, provider)` | orchestrator.py ~370 | Uses real tiktoken; o200k_base for OpenAI, cl100k_base for Anthropic |
| 12 | `trim_messages_to_context_window(msgs, ctx, provider)` | orchestrator.py ~400 | Raises ToolError if context_window is None; keeps 85% budget |
| 13 | `build_system_prompt()` | orchestrator.py ~450 | Lists only registered bridges, not hardcoded set |
| 14 | `Orchestrator.start_session(provider, model, binary_path, ...)` | orchestrator.py ~900 | Creates session; raises ValueError if provider not available |
| 15 | `Orchestrator.process_user_input(text)` | orchestrator.py ~1000 | Full agent loop: validates tool schemas, sends to provider, dispatches tool calls, rollback on failure |
| 16 | `Orchestrator.add_binary(path, run_bridge_analysis)` | orchestrator.py ~1100 | Parses real binary, populates BinaryInfo, fires bridge analysis callback |
| 17 | `Orchestrator.request_confirmation(call)` | orchestrator.py ~1200 | Gates destructive calls; resolves via async callback |
| 18 | `Orchestrator.cancel()` | orchestrator.py ~1250 | Cancels in-flight confirmation futures |
| 19 | `Orchestrator.set_confirmation_level(level)` | orchestrator.py ~1280 | Mutates the stored config |
| 20 | `Orchestrator.get_current_bridge_analysis(name)` | orchestrator.py ~1300 | Returns cached BridgeAnalysisSummary |
| 21 | `Orchestrator.load_session(session_id)` | orchestrator.py ~1320 | Sets SessionManager.current and starts auto-save |
| 22 | `Orchestrator.shutdown()` | orchestrator.py ~1400 | Cleanup: cancels tasks, closes session, shuts down registry |
| 23 | `Orchestrator.list_sessions()` | orchestrator.py ~1350 | Queries SessionStore for all sessions |
| 24 | `Orchestrator.delete_session(session_id)` | orchestrator.py ~1360 | Deletes from SQLite |
| 25 | Orchestrator agent loop max_iterations guard | orchestrator.py ~1050 | Exits loop after N iterations |
| 26 | Orchestrator agent loop timeout guard | orchestrator.py ~1060 | Raises if total elapsed exceeds timeout_seconds |
| 27 | Orchestrator broken tool schema detection | orchestrator.py ~970 | Raises ToolError("Tool schema validation failed") |
| 28 | Orchestrator missing context window detection | orchestrator.py ~980 | Raises ToolError("context window") before provider call |
| 29 | Orchestrator context window override | orchestrator.py ~985 | Bypasses provider lookup |
| 30 | Orchestrator turn rollback on failure | orchestrator.py ~1080 | User message not persisted when agent loop fails |
| 31 | `Orchestrator.set_message_callback` | orchestrator.py ~500 | Fires for user and assistant messages |
| 32 | `Orchestrator.set_tool_call_callback` | orchestrator.py ~510 | Fires for each dispatched tool call |
| 33 | `Orchestrator.set_tool_result_callback` | orchestrator.py ~520 | Fires with ToolResult after each dispatch |
| 34 | `Orchestrator.set_bridge_analysis_callback` | orchestrator.py ~530 | Fires with BridgeAnalysisSummary after add_binary |
| 35 | `Session.add_tag(tag)` | session.py ~200 | Strips whitespace; raises ValueError for empty |
| 36 | `Session.remove_tag(tag)` | session.py ~215 | Returns bool; persists through store |
| 37 | `Session.add_binary(info)` | session.py ~230 | Appends to binaries; sets active_binary |
| 38 | `Session.add_message(msg)` | session.py ~240 | Appends to messages list |
| 39 | `Session.set_tool_state(state)` | session.py ~250 | Stores at ToolName key; updates updated_at; returns None |
| 40 | `Session.clear_tool_state(tool)` | session.py ~265 | Removes entry; returns True/False |
| 41 | `SessionStore` SQLite persistence | session.py ~500 | BEGIN IMMEDIATE transactions; all field types serialized |
| 42 | `SessionStore.load(session_id)` | session.py ~600 | Deserializes from SQLite |
| 43 | `SessionStore.export_to_json(path)` | session.py ~700 | Exports all sessions as JSON |
| 44 | `SessionStore.import_from_json(path, replace)` | session.py ~750 | Imports; replace=True clears existing |
| 45 | `SessionManager.create(provider, model)` | session.py ~900 | Creates Session, persists to store |
| 46 | `SessionManager.update(session)` | session.py ~920 | Runs SQLite I/O in worker thread; serialized by asyncio.Lock |
| 47 | `SessionManager.load(session_id)` | session.py ~940 | Sets manager.current after load |
| 48 | `SessionManager.import_json(path, replace)` | session.py ~970 | Delegates to store; replace logic |
| 49 | `SessionManager.is_auto_saving` | session.py ~990 | Property; True after create, False after close |
| 50 | `SessionManager.close()` | session.py ~1000 | Stops auto-save loop; sets is_auto_saving → False |
| 51 | Auto-save loop resilience | session.py ~1050 | Survives transient failures; re-arms |
| 52 | `HexDocumentLike` / `HexDocumentFull` Protocol bodies | session.py ~100 | Declarative only (no concrete logic) |
| 53 | `ProcessManager` singleton | process_manager.py ~80 | get_instance / reset_instance / thread-safety |
| 54 | `ProcessManager.run_tracked(args, name, ...)` | process_manager.py ~200 | Wraps Popen; registers, communicates, unregisters |
| 55 | `run_tracked` raises ProcessStateError | process_manager.py ~240 | When returncode is None |
| 56 | `ProcessManager.run_tracked_async(...)` | process_manager.py ~280 | Async variant; timeout, check, concurrent |
| 57 | `ProcessManager.register(proc, name)` | process_manager.py ~320 | Adds to tracking dict |
| 58 | `ProcessManager.unregister(pid)` | process_manager.py ~335 | Removes from tracking dict |
| 59 | `ProcessManager.register_external_pid(pid, ...)` | process_manager.py ~350 | Validates PID exists via _pid_exists; raises ValueError for dead PID |
| 60 | `ProcessManager.unregister_external_pid(pid)` | process_manager.py ~370 | Returns True/False |
| 61 | `ProcessManager.terminate_external_pid(pid, force)` | process_manager.py ~390 | Kills and unregisters; handles nonexistent |
| 62 | `ProcessManager._pid_exists_windows(pid)` | process_manager.py ~420 | Uses kernel32.OpenProcess with psutil fallback |
| 63 | `ProcessManager._sync_cleanup()` | process_manager.py ~500 | Terminates all tracked and external processes |
| 64 | `ProcessManager.cleanup_all_async()` | process_manager.py ~520 | Async cleanup of all tracked processes |
| 65 | `ProcessManager.install_handlers()` | process_manager.py ~550 | Registers atexit + signal handlers |
| 66 | `ProcessManager.uninstall_handlers()` | process_manager.py ~570 | Clears atexit registration |
| 67 | `ProcessManager._atexit_cleanup()` | process_manager.py ~590 | Deduplication guard |
| 68 | `ProcessManager._signal_handler(sig, frame)` | process_manager.py ~610 | Non-blocking; delegates to thread or asyncio.create_task |
| 69 | `TrackedProcess.is_running` | process_manager.py ~150 | Property; True for live process |
| 70 | `ProcessManager.process_count`, `running_count` | process_manager.py ~170 | Live counts |
| 71 | `ProcessManager.get_all_tracked()`, `get_running_processes()` | process_manager.py ~180 | Filtered lists |
| 72 | `AnalysisAggregator.aggregate(name, binary_info)` | analysis_aggregator.py ~50 | Seeds from BinaryInfo; queries Ghidra + Cutter |
| 73 | `AnalysisAggregator._collect_from_static_bridge` | analysis_aggregator.py ~100 | Collects imports/exports/functions/strings; handles exceptions |
| 74 | `AnalysisAggregator._deduplicate_imports(imports)` | analysis_aggregator.py ~180 | Key: (dll, function, ordinal) |
| 75 | `AnalysisAggregator._deduplicate_exports(exports)` | analysis_aggregator.py ~210 | Key: (name, ordinal, address) |
| 76 | `aggregate` complete=True only when bridge contributes | analysis_aggregator.py ~75 | Flag logic |
| 77 | `aggregate` source_bridges list | analysis_aggregator.py ~80 | Tracks which bridges contributed |
| 78 | `aggregate` with Cutter bridge | analysis_aggregator.py ~90 | Parallel to Ghidra path |
| 79 | `CustomExpressionNode.process(data, params)` | transform_pipeline.py ~200 | Per-byte restricted-AST evaluator; masks result with & 0xFF |
| 80 | `_eval_ast_node` arithmetic ops | transform_pipeline.py ~280 | +, -, *, //, %, ** |
| 81 | `_eval_ast_node` bitwise ops | transform_pipeline.py ~295 | <<, >>, \|, ^, &, ~, unary - |
| 82 | `_eval_ast_node` comparison ops | transform_pipeline.py ~310 | >, <, ==, !=, >=, <= |
| 83 | `_eval_ast_node` boolean/conditional ops | transform_pipeline.py ~320 | and, or, IfExp ternary |
| 84 | `_eval_ast_node` unknown variable → ExpressionError | transform_pipeline.py ~340 | |
| 85 | `_eval_ast_node` string constant → UnsupportedConstantTypeError | transform_pipeline.py ~355 | |
| 86 | `_eval_ast_node` function call → ExpressionError | transform_pipeline.py ~360 | |
| 87 | `RegexReplaceNode.process(data, params)` | transform_pipeline.py ~400 | Requires "pattern"; defaults to empty replacement |
| 88 | `RepeatNode.process(data, params)` | transform_pipeline.py ~450 | Requires count >= 1 |
| 89 | `TruncateNode.process(data, params)` | transform_pipeline.py ~470 | Requires length >= 0 |
| 90 | `PadNode.process(data, params)` | transform_pipeline.py ~490 | Fill byte 0-255; default NUL |
| 91 | `TransformPipeline.execute(data)` | transform_pipeline.py ~560 | Sequential application |
| 92 | `TransformPipeline.preview(data)` | transform_pipeline.py ~580 | Captures intermediates per step |
| 93 | `TransformPipeline.add_step`, `remove_step`, `move_step`, `clear` | transform_pipeline.py ~600 | Step management |
| 94 | `RustTransformNode.process(data, params)` | transform_pipeline.py ~650 | Dispatches to hexcore; param coercion |
| 95 | `HexcoreUnavailableError` raised when hexcore absent | transform_pipeline.py ~670 | |
| 96 | `get_all_transform_nodes()` | transform_pipeline.py ~700 | Enumerates Rust + Python nodes |
| 97 | `ToolRegistry.execute_tool_call(tool, func, args)` | tools.py ~200 | ToolName enum lookup → bridge → getattr → capability gate → dispatch |
| 98 | `execute_tool_call` dotted function name routing | tools.py ~210 | Strips "tool." prefix |
| 99 | `execute_tool_call` case-insensitive tool name | tools.py ~215 | Lowercases before ToolName lookup |
| 100 | `execute_tool_call` ToolError: unknown tool | tools.py ~220 | _ERR_UNKNOWN_TOOL |
| 101 | `execute_tool_call` ToolError: not registered | tools.py ~230 | _ERR_NOT_REGISTERED |
| 102 | `execute_tool_call` ToolError: unknown function | tools.py ~240 | _ERR_UNKNOWN_FUNC |
| 103 | `execute_tool_call` ToolError: not callable | tools.py ~245 | _ERR_NOT_CALLABLE |
| 104 | `execute_tool_call` ToolError: missing capability | tools.py ~255 | _ERR_MISSING_CAPABILITY |
| 105 | `ToolRegistry.initialize()` | tools.py ~100 | Instantiates 7 bridges; auto-inits _LOCAL_INIT_TOOLS |
| 106 | `ToolRegistry.shutdown()` | tools.py ~130 | Clears _bridges; sets _initialized=False; continues on ToolError |
| 107 | `ToolRegistry.get_tool_definitions()` | tools.py ~160 | Returns each bridge's real tool_definition |
| 108 | `ToolRegistry.set_session(session)` | tools.py ~170 | Propagates to all registered bridges |
| 109 | `ToolRegistry.register_bridge(name, bridge)` | tools.py ~185 | Adds to _bridges; sets session if active |
| 110 | `ToolRegistry.get(tool_name)` | tools.py ~190 | Returns bridge or None |
| 111 | `ToolRegistry.get_available_tools()` | tools.py ~195 | List of registered ToolName values |
| 112 | `ToolRegistry` typed getters (get_hex_editor_bridge, etc.) | tools.py ~300 | Raise ToolError if not registered or wrong type |
| 113 | `ToolRegistry.initialize_tool(tool_name)` | tools.py ~140 | Local-init vs installer path |
| 114 | Bridge `set_session` propagation (pre-registration) | tools.py ~170 | Bridges registered before set_session receive it |
| 115 | Bridge `set_session` propagation (post-registration) | tools.py ~185 | Bridges registered after set_session inherit it |
| 116 | Bridge `set_session(None)` detach | tools.py ~175 | Severs bridge-to-session wiring |
| 117 | Bridge lifecycle: connect → publish ToolState | bridges/base.py | On initialize() |
| 118 | Bridge lifecycle: attach → publish ToolState | bridges/base.py | On process attach |
| 119 | Bridge lifecycle: error → publish ToolState | bridges/base.py | On last_error update |
| 120 | Bridge lifecycle: shutdown → clear ToolState | bridges/base.py | On _finalize_shutdown |

---

## 2. Test File Inventory

| Test file | Line count | Role |
|-----------|-----------|------|
| `tests/test_core/test_orchestrator.py` | 264 | Unit: OrchestratorConfig, OrchestratorStats, initial state, provider_registry identity, DESTRUCTIVE_PATTERNS, start_session ValueError, cancel future |
| `tests/test_core/test_orchestrator_audit6.py` | ~900 | Unit+Integration: extract_imports/exports (hand-assembled ELF64/MachO64), classify_tool_call, BRIDGE_DESTRUCTIVE_METHODS coverage, estimate_tokens (tiktoken oracle), trim_messages_to_context_window, agent loop rollback/persist, broken schema/missing context window errors, _FakeProvider/_StubBridge real subclasses |
| `tests/test_core/test_realcov_05a_orchestration.py` | 738 | E2E: Full agent loop (real binary, real bridge dispatch), add_binary (real PE, SHA256 oracle), start_session with binary_path (real ELF), Session.add_binary/add_message round-trip, message/tool/bridge callbacks |
| `tests/test_core/test_session_audit6.py` | ~600 | Unit+Integration: auto-save loop resilience (3 failures → 4th success), set_tool_state (exact SQLite round-trip), add_tag/remove_tag (whitespace/empty/ValueError), worker thread for update(), concurrent serialization, Protocol AST inspection |
| `tests/test_core/test_tools_audit6.py` | ~300 | Unit: CutterBridge auto-init, log payload inspection (tool_name string, correct key), ToolRegistry.shutdown clears bridges on ToolError |
| `tests/test_core/test_realcov_05b_tools.py` | 362 | Integration: execute_tool_call (real HexEditorBridge, real PE MZ magic), dotted name, case-insensitive name, capability gate real rejection, get_tool_definitions schema match, set_session state propagation, register_bridge dispatch |
| `tests/test_core/test_realcov_05b_analysis_aggregator.py` | 497 | Integration: aggregate (no bridges, real PE sections/exports/imports), Ghidra bridge contributing (ntdll.dll data), string derivation (DLL names), deduplication exact-key verification (imports + exports), ELF binary metadata, failing bridge (notes + complete=False) |
| `tests/test_core/test_analysis_aggregator.py` | 325 | Integration: same paths as 05b with real PE and failing bridge; deduplication key verification |
| `tests/test_core/test_realcov_07a_transform_pipeline.py` | 499 | Unit+Integration: CustomExpressionNode (all operator types, real PE bytes), _eval_ast_node (21 parametrized cases), RegexReplaceNode (real MZ magic, empty replacement, bytes replacement, error paths), RepeatNode/TruncateNode/PadNode (edge cases), TransformPipeline execute/preview/step management, RustTransformNode (base64 vs stdlib, roundtrip, param coercion), HexcoreUnavailableError |
| `tests/test_core/test_process_manager.py` | 1075 | Unit+Integration: singleton, run_tracked (stdout/stderr/exit/timeout/cwd/env/bytes/check/lifecycle), run_tracked_async (concurrent), register_external_pid/unregister/terminate (Windows+Unix), _sync_cleanup (tracked + external), cleanup_all_async, install/uninstall handlers, TrackedProcess.is_running, process_count/running_count |
| `tests/test_core/test_process_manager_audit6.py` | 335 | Unit: register_external_pid validates PID (zero, dead, live, self), _atexit_cleanup deduplication, _signal_handler non-blocking (elapsed < 1s proof), _signal_handler with running event loop |
| `tests/test_audit7/core_orchestration/test_tool_registry_session.py` | 241 | Unit: set_session propagates to pre-registered bridges, post-registration bridges inherit session, set_session(None) detach no-op publish |
| `tests/test_audit7/core_orchestration/test_tool_state_lifecycle.py` | 242 | Unit: bridge publishes connect/attach/error/detach to Session.tool_states, set_session late-attach publishes immediately, set_session(None) no subsequent publish |

---

## 3. Coverage Classification

### REAL gates (falsifiable, independently verified)

| Operation | Test file | Verdict | Oracle |
|-----------|-----------|---------|--------|
| OrchestratorConfig defaults | test_orchestrator.py:62 | REAL | Constant values |
| OrchestratorStats.to_dict (all 10 fields) | test_orchestrator.py:103 | REAL | Known constants + rolling average formula |
| BRIDGE_DESTRUCTIVE_METHODS covers all 7 ToolName values | test_orchestrator_audit6.py | REAL | ToolName enum iteration |
| classify_tool_call: frida.get_hooks → read_only | test_orchestrator_audit6.py | REAL | Constant |
| classify_tool_call: sandbox.destroy → destructive | test_orchestrator_audit6.py | REAL | Constant |
| classify_tool_call: unknown bridge → unknown | test_orchestrator_audit6.py | REAL | Constant |
| is_destructive_operation: unknown bridge → True | test_orchestrator_audit6.py | REAL | Constant (fail-safe) |
| extract_imports: ELF64 named symbols (exact names) | test_orchestrator_audit6.py | REAL | Hand-assembled binary fixtures |
| extract_exports: ELF64 exact symbol name | test_orchestrator_audit6.py | REAL | Hand-assembled binary |
| extract_imports: MachO64 (exact _audit6_macho_import) | test_orchestrator_audit6.py | REAL | Hand-assembled binary |
| extract_imports/exports on real PE | test_realcov_05a:607 | REAL | Real kernel32.dll / SHA256 oracle |
| estimate_tokens: o200k_base oracle (OpenAI) | test_orchestrator_audit6.py | REAL | Real tiktoken encoder |
| estimate_tokens: cl100k_base oracle (Anthropic) | test_orchestrator_audit6.py | REAL | Real tiktoken encoder |
| trim_messages_to_context_window(None) → ToolError | test_orchestrator_audit6.py | REAL | Exception type + message |
| CJK content trimming > naive len//4 | test_orchestrator_audit6.py | REAL | Real tiktoken oracle |
| Broken tool schema → ToolError | test_orchestrator_audit6.py | REAL | Exception type + message |
| Missing context window → ToolError before provider | test_orchestrator_audit6.py | REAL | Exception type + message |
| Context window override bypasses provider lookup | test_orchestrator_audit6.py | REAL | Constant |
| build_system_prompt lists only registered bridges | test_orchestrator_audit6.py | REAL | Set equality |
| Agent loop turn rollback on failure | test_orchestrator_audit6.py | REAL | SQLite load after failure — no user message |
| Agent loop user message persisted on success | test_orchestrator_audit6.py | REAL | SQLite load confirms content |
| Orchestrator.cancel resolves in-flight future → False | test_orchestrator.py:189 | REAL | Future.cancelled() + awaited result |
| start_session no provider → ValueError | test_orchestrator.py:177 | REAL | Exception type + message |
| Full end-to-end agent loop (2 turns, real bridge, real PE) | test_realcov_05a:537 | REAL | chat_call_count==2, MZ magic, SHA256, LoadLibrary in imports |
| add_binary: real PE SHA256, file_type, sections, imports | test_realcov_05a:589 | REAL | hashlib SHA256 oracle, lief fields |
| start_session with binary_path: real ELF metadata | test_realcov_05a:638 | REAL | SHA256 oracle, file_type="elf" |
| Session.add_binary / add_message SQLite round-trip | test_realcov_05a:675 | REAL | Field-by-field reload verification |
| Message callback fires for user and assistant messages | test_realcov_05a:714 | REAL | Role/content pair membership |
| load_session sets SessionManager.current | test_orchestrator_audit6.py | REAL | Identity check |
| Auto-save loop: 3 failures → 4th success (exact count) | test_session_audit6.py | REAL | Counter oracle |
| is_auto_saving True after create / False after close | test_session_audit6.py | REAL | Boolean state |
| set_tool_state: exact object at ToolName key | test_session_audit6.py | REAL | Identity + updated_at change |
| set_tool_state SQLite round-trip (all fields) | test_session_audit6.py | REAL | Field-by-field comparison |
| set_tool_state overwrites previous | test_session_audit6.py | REAL | Overwrite verified |
| Multiple tools independent; clear_tool_state True/False | test_session_audit6.py | REAL | Boolean + key absence |
| add_tag: strips whitespace, True/False, ValueError for empty | test_session_audit6.py | REAL | Return value + exception |
| remove_tag: True/False, persists through store | test_session_audit6.py | REAL | Return value + reload |
| SessionManager.update runs in worker thread (not event loop) | test_session_audit6.py | REAL | Thread ID oracle |
| Concurrent update() serialized (max_concurrent == 1) | test_session_audit6.py | REAL | Overlap counter oracle |
| Protocol bodies declarative (AST inspection) | test_session_audit6.py | REAL | AST node count |
| ProcessManager singleton identity | test_process_manager.py:127 | REAL | `is` identity check |
| reset_instance creates new instance | test_process_manager.py:139 | REAL | `is not` |
| run_tracked stdout + unregister lifecycle | test_process_manager.py:155 | REAL | Content + count oracle |
| run_tracked exit code 42 | test_process_manager.py:199 | REAL | Exact exit code |
| run_tracked check=True → CalledProcessError | test_process_manager.py:215 | REAL | Exception type + returncode |
| run_tracked timeout → TimeoutExpired | test_process_manager.py:233 | REAL | Exception type |
| run_tracked registers mid-execution (thread snapshot) | test_process_manager.py:345 | REAL | Thread event + name in list |
| run_tracked process_count: baseline → +1 → baseline | test_process_manager.py:394 | REAL | Counter oracle |
| run_tracked_async concurrent (< 1.5s for two 0.5s tasks) | test_process_manager.py:489 | REAL | Elapsed time oracle |
| register_external_pid stores exact fields | test_process_manager.py:521 | REAL | Field-by-field assertion |
| register_external_pid rejects dead PID → ValueError | test_process_manager_audit6.py:127 | REAL | Exception + registry absence |
| register_external_pid rejects PID 0 → ValueError | test_process_manager_audit6.py:116 | REAL | Exception + registry absence |
| register_external_pid accepts live PID | test_process_manager_audit6.py:148 | REAL | Registry membership |
| terminate_external_pid kills real process (Windows) | test_process_manager.py:663 | REAL | exit_code != 0 |
| _sync_cleanup terminates tracked + external PIDs | test_process_manager.py:723 | REAL | wait() returns + count == 0 |
| cleanup_all_async terminates all | test_process_manager.py:785 | REAL | wait() returns + count == 0 |
| _atexit_cleanup calls _sync_cleanup exactly once | test_process_manager_audit6.py:181 | REAL | Counter oracle |
| _signal_handler non-blocking (elapsed < 1s proof) | test_process_manager_audit6.py:249 | REAL | perf_counter oracle |
| _signal_handler uses loop when available | test_process_manager_audit6.py:289 | REAL | cleanup_started event |
| AnalysisAggregator.aggregate: real PE, no bridges | test_analysis_aggregator.py:178, test_realcov_05b_analysis_aggregator.py:234 | REAL | file_type, .text section, imports exact set, complete=False |
| aggregate: kernel32.dll exports real WinAPI symbols | test_realcov_05b_analysis_aggregator.py:261 | REAL | Named constant membership |
| aggregate: ELF binary metadata flows through | test_realcov_05b_analysis_aggregator.py:281 | REAL | file_type, section count |
| aggregate: Ghidra bridge contributing real ntdll.dll data | test_realcov_05b_analysis_aggregator.py:305 | REAL | complete=True, source_bridges, export set intersection |
| aggregate: DLL-name strings from real bridge | test_realcov_05b_analysis_aggregator.py:332 | REAL | Set subset proof |
| _deduplicate_imports: exact (dll,func,ordinal) key set | test_realcov_05b_analysis_aggregator.py:353 | REAL | len(keys)==len(set(keys)) + set equality |
| _deduplicate_exports: exact (name,ordinal,addr) key set | test_realcov_05b_analysis_aggregator.py:379 | REAL | len(keys)==len(set(keys)) + set equality |
| failing bridge: notes recorded, PE data preserved, complete=False | test_realcov_05b_analysis_aggregator.py:405 | REAL | Note content + section check |
| CustomExpressionNode b ^ 0x55 over real PE (256 bytes) | test_realcov_07a:93 | REAL | Independent Python XOR oracle |
| CustomExpressionNode (b + i) & 0xFF | test_realcov_07a:105 | REAL | Independent oracle |
| CustomExpressionNode nibble-swap round-trip | test_realcov_07a:116 | REAL | Double-application restores original |
| CustomExpressionNode negative masking → 0xFF | test_realcov_07a:128 | REAL | Known constant (0-1)&0xFF == 0xFF |
| CustomExpressionNode conditional (IfExp) | test_realcov_07a:136 | REAL | Independent oracle |
| _eval_ast_node: 21 operators, b=10 → exact values | test_realcov_07a:166 | REAL | Parametrized constant oracle |
| _eval_ast_node: unknown variable → ExpressionError | test_realcov_07a:202 | REAL | Exception type + message |
| _eval_ast_node: string constant → UnsupportedConstantTypeError | test_realcov_07a:208 | REAL | Exception type |
| _eval_ast_node: function call → ExpressionError | test_realcov_07a:213 | REAL | Exception type + message |
| RegexReplaceNode: real MZ→XX byte-for-byte | test_realcov_07a:221 | REAL | Byte slice equality |
| RegexReplaceNode: empty replacement removes pattern | test_realcov_07a:234 | REAL | Byte equality |
| RegexReplaceNode: missing pattern → TransformParamError | test_realcov_07a:247 | REAL | Exception type + message |
| RegexReplaceNode: invalid regex → TransformParamError | test_realcov_07a:253 | REAL | Exception type + message |
| RepeatNode: real PE bytes × 3 | test_realcov_07a:263 | REAL | bytes * 3 oracle |
| RepeatNode: count=0 → TransformParamError | test_realcov_07a:273 | REAL | Exception type + message |
| TruncateNode: real PE bytes[:16] | test_realcov_07a:285 | REAL | Slice equality |
| TruncateNode: length > data → full input | test_realcov_07a:295 | REAL | Identity |
| PadNode: extends with fill byte | test_realcov_07a:312 | REAL | Byte-level equality |
| PadNode: default fill is NUL | test_realcov_07a:318 | REAL | Byte-level equality |
| PadNode: no-op when already long | test_realcov_07a:323 | REAL | Identity |
| TransformPipeline.execute: 3-step chain (Truncate→XOR→Repeat) | test_realcov_07a:342 | REAL | Independent step-by-step oracle |
| TransformPipeline.preview: named intermediates | test_realcov_07a:357 | REAL | Name list + byte slice equality |
| TransformPipeline step management (move, remove, clear) | test_realcov_07a:371 | REAL | Name list order + False return |
| TransformPipeline empty pipeline → input unchanged | test_realcov_07a:385 | REAL | Identity |
| RustTransformNode base64 == stdlib base64.b64encode | test_realcov_07a:397 | REAL | stdlib oracle |
| HexcoreUnavailableError when hexcore absent | test_realcov_07a:477 | REAL | Both paths: success or exception |
| get_all_transform_nodes: Python set subset | test_realcov_07a:449 | REAL | Set membership |
| execute_tool_call: real HexEditorBridge, real PE size | test_realcov_05b_tools.py:90 | REAL | file.stat().st_size oracle |
| execute_tool_call: real MZ magic bytes | test_realcov_05b_tools.py:113 | REAL | "4D 5A" constant |
| execute_tool_call: dotted name routes to method | test_realcov_05b_tools.py:146 | REAL | Size oracle |
| execute_tool_call: case-insensitive (X64DBG == x64dbg) | test_realcov_05b_tools.py:169 | REAL | Direct bridge oracle |
| Capability gate rejects scripting-disabled bridge | test_realcov_05b_tools.py:202 | REAL | ToolError + message |
| get_tool_definitions: all 7 bridge schemas | test_realcov_05b_tools.py:230 | REAL | bridge.tool_definition equality |
| set_session: state propagates after open (target_path) | test_realcov_05b_tools.py:275 | REAL | ToolState field |
| register_bridge dispatch (HexEditorBridge, alignment_grid) | test_realcov_05b_tools.py:313 | REAL | Direct bridge oracle |
| ToolRegistry.shutdown clears _bridges on ToolError | test_tools_audit6.py | REAL | _bridges empty + _initialized=False |
| set_session propagates to pre-registered bridges | test_tool_registry_session.py:143 | REAL | set_session_calls >= 1 + ToolState in session |
| set_session attaches newly-registered bridges | test_tool_registry_session.py:169 | REAL | ToolState in session + connected=True |
| set_session(None) detach no-op publish | test_tool_registry_session.py:189 | REAL | Falsifiability proof in docstring; connected remains True |
| Bridge publish connect → ToolState | test_tool_state_lifecycle.py:121 | REAL | connected=True, last_error=None |
| Bridge publish attach → ToolState | test_tool_state_lifecycle.py:136 | REAL | process_attached=True, target_path |
| Bridge publish error → last_error | test_tool_state_lifecycle.py:158 | REAL | Exact error string |
| Bridge shutdown clears ToolState | test_tool_state_lifecycle.py:171 | REAL | Key absence |
| Full lifecycle cycle (connect/attach/error/detach) | test_tool_state_lifecycle.py:185 | REAL | Multi-step state progression |
| set_session late-attach publishes immediately | test_tool_state_lifecycle.py:216 | REAL | ToolState appears after set_session |
| set_session(None) no subsequent publish | test_tool_state_lifecycle.py:229 | REAL | last_error remains None after fake_error |

---

## 4. Weak / No Coverage

| Operation | Verdict | Reason |
|-----------|---------|--------|
| `Orchestrator.shutdown()` | NO COVERAGE | No test drives the shutdown sequence; ToolRegistry + session + task cancellation all untested |
| `Orchestrator.list_sessions()` | NO COVERAGE | No test calls this method |
| `Orchestrator.delete_session(session_id)` | NO COVERAGE | No test covers the delete-from-SQLite path |
| `Orchestrator` agent loop max_iterations guard | NO COVERAGE | No test runs a loop until max_iterations is hit |
| `Orchestrator` agent loop timeout guard | NO COVERAGE | No test triggers the timeout_seconds path |
| Confirmation gate: ConfirmationLevel.ALL vs. DESTRUCTIVE in live loop | NO COVERAGE | cancel() test is unit-level only; no agent loop with a real destructive call pending confirmation |
| `SessionStore.export_to_json` / `import_from_json` | NO COVERAGE | No test exercises JSON export or import paths |
| `SessionManager.import_json(path, replace=True)` | NO COVERAGE | The replace-all-sessions branch is untested |
| `ProcessManager.run_tracked` ProcessStateError (returncode is None) | NO COVERAGE | No test corrupts a subprocess to trigger this |
| `ProcessManager._pid_exists_windows` kernel32 fallback path | WEAK | Only the overall register/reject behavior is tested; the two-stage kernel32→psutil fallback in _pid_exists_windows is not separately verified |
| `AnalysisAggregator.aggregate` with Cutter bridge | NO COVERAGE | Only GhidraBridge is exercised; the Cutter path is a parallel branch never hit |
| `AnalysisAggregator.aggregate` with both Ghidra + Cutter bridges | NO COVERAGE | Merged-bridge scenario never tested |
| `TransformPipeline` mid-pipeline step error propagation | NO COVERAGE | No test covers what happens when a step raises mid-chain |
| `TransformPipeline.to_dict` / `from_dict` serialization | NO COVERAGE (if exists) | Not found in test files |
| `execute_tool_call` with a native coroutine bridge method | WEAK | Tests drive synchronous methods through asyncio.to_thread; the async-method direct dispatch path (where the method is itself a coroutine) is not independently verified |
| `initialize_tool(GHIDRA)` / `initialize_tool(X64DBG)` installer path | NO COVERAGE | test_tools_audit6.py only covers the local-init path |
| `ToolRegistry` typed getters raising ToolError when bridge absent | WEAK | Happy-path typed getters tested; ToolError on absence not explicitly exercised |
| `RustTransformNode` param coercion with invalid params | WEAK | Valid coercions (hex string, integer) tested; invalid hex string or out-of-range integer not verified |
| `RegexReplaceNode` with bytes replacement that is a str type | WEAK | Only bytes and no-replacement tested; str type replacement path not verified |

---

## 5. Worst Offenders (Fake Gate / Anti-Pattern)

After reading all test files for this section, no tests in the confirmed coverage set exhibit the forbidden anti-patterns. The suite does not use `MagicMock`, `AsyncMock`, `patch`, or `unittest.mock` anywhere in the files read. All assertions on bridge outputs check real bytes, real file sizes, real SHA256 digests, real symbol names from real System32 DLLs, or independently computed reference values (tiktoken encoders, Python arithmetic oracles, stdlib base64).

**Historical note:** `tests/test_core/test_analysis_aggregator.py` notes in its module docstring that it previously mocked the entire bridge layer (`MagicMock` registry, `AsyncMock` bridge methods). Those stubs were replaced and the current file uses real lief parsing against real PE files. No mock remnants were found in the file as it stands today.

The sole concern below is not a mock but a structural gap:

**Conditional skip overuse in RustTransformNode tests** (`test_realcov_07a:404–444`): Every RustTransformNode test has `if not _hexcore_present(): pytest.skip(...)`. This is acceptable because the skip gate is environment-gated (hexcore genuinely absent), not logic-gated — the skip correctly maps to a missing capability. However, if hexcore is always absent in CI this entire class becomes dead coverage. This is flagged as a monitoring concern, not a fake-gate rejection.

---

## 6. Edge-Case Coverage Scorecard

| Dimension | Status |
|-----------|--------|
| Empty input (empty pipeline, no binaries) | COVERED — empty TransformPipeline returns input; no-bridge aggregate tested |
| Maximal/complex input (real PE DLLs, real ELF) | COVERED — kernel32.dll, ntdll.dll, user32.dll; committed ELF corpus |
| Malformed binary (truncated, unsupported format) | PARTIAL — lief parse failure path tested via ValueError in orchestrator fixture; ELF/MachO fixtures tested; truncated binary not explicitly tested |
| Unknown tool name / unknown function / not callable | COVERED — execute_tool_call ToolError paths |
| Missing capability gate | COVERED — scripting-disabled hex editor |
| Provider unavailable | COVERED — start_session ValueError |
| Agent loop failure / rollback | COVERED — SQLite verified |
| Bridge failure mid-collection | COVERED — FailingGhidraBridge raises; notes verified |
| Concurrent session access | COVERED — serialized update() |
| Dead PID registration | COVERED — guaranteed_dead_pid test |
| Signal handler non-blocking | COVERED — perf_counter oracle |
| Auto-save loop transient failures | COVERED — 3 failures exact count |
| Context window None | COVERED — ToolError before provider |
| CJK token estimation vs naive | COVERED — tiktoken oracle |
| Destructive op confirmation | PARTIAL — unit-level cancel test; no live agent loop with confirmation gating |
| Timeout guard | NO COVERAGE |
| Max iterations guard | NO COVERAGE |
| JSON export / import | NO COVERAGE |
| Cutter bridge aggregation | NO COVERAGE |
| Mid-pipeline error propagation | NO COVERAGE |

---

## 7. Section Scores

### Coverage score
- Operations with ≥1 REAL gate: approximately 105 of 120 enumerated operations.
- Operations with NO COVERAGE: approximately 12 (Orchestrator.shutdown, list_sessions, delete_session, max_iterations guard, timeout guard, live confirmation loop, SessionStore.export/import_from_json, SessionManager.import_json, ProcessManager.run_tracked ProcessStateError, AnalysisAggregator Cutter path, both-bridges path, mid-pipeline error).
- Operations with WEAK coverage: approximately 4 (_pid_exists_windows fallback, async coroutine dispatch, typed getter ToolError on absence, invalid RustTransformNode params).

**Gate score: 87.5% (105/120)**

### Edge-case score
- Of 20 edge-case dimensions above: 13 fully COVERED, 2 PARTIAL, 5 NO COVERAGE.

**Edge-case score: 65% (13/20)**

---

## 8. Remediation Recommendations

### Priority 1 — Missing gates on critical paths

**`Orchestrator.shutdown()`**
- What to assert: After `await orch.shutdown()`, assert `orch.state == "idle"`, `orch.current_session is None`, `tool_registry.get_available_tools() == []` (all bridges shut down), and that any background auto-save task is no longer running (probe `session_manager.is_auto_saving`).
- Independent oracle: Construct with real registry and session; call shutdown; then call execute_tool_call and assert ToolError rather than a result.

**Agent loop max_iterations guard**
- What to assert: Construct a `_ScriptedProvider` that always returns a ToolCall (never a final text turn). Configure `OrchestratorConfig(max_iterations=3, ...)`. After `process_user_input`, assert that a `ToolError` (or `OrchestratorError`) is raised or the loop exits with exactly 3 total_tool_calls. Probe `orch.stats.total_tool_calls == 3`.
- Independent oracle: The counter itself — `assert orch.stats.total_tool_calls == config.max_iterations`.

**Agent loop timeout guard**
- What to assert: Use a scripted provider that sleeps (via `asyncio.sleep`) before each response. Set `OrchestratorConfig(timeout_seconds=0.1, ...)`. Assert that `asyncio.TimeoutError` or the configured timeout exception propagates from `process_user_input`.

**Confirmation gate in a live agent loop**
- What to assert: Construct an orchestrator with `ConfirmationLevel.DESTRUCTIVE`, a scripted provider that returns a destructive tool call (e.g., `frida.write_memory`), and a confirmation callback that returns a future immediately resolved to `True` (approved) or `False` (denied). Assert that when denied, the tool is not dispatched (bridge call count == 0) and when approved, it is dispatched (call count == 1).

**`Orchestrator.list_sessions()` / `delete_session()`**
- What to assert: Create two sessions via `manager.create`, then `list_sessions()` must return exactly 2. After `delete_session(session1.id)`, `list_sessions()` must return exactly 1 and `store.load(session1.id)` must return `None`.

**`SessionStore.export_to_json` / `import_from_json`**
- What to assert: Populate a store with a real session (real binary, real messages from lief-parsed PE). Export to tmp_path JSON. Construct a new `SessionStore` at a different path. Call `import_from_json(json_path)`. Reload the session by ID and assert `sha256 == original.sha256`, `len(messages) == original message count`, `len(sections) == original section count`.
- Independent oracle: The original session fields themselves — no re-parsing needed.

**`AnalysisAggregator.aggregate` with Cutter bridge**
- What to assert: Register a `_RealDataCutterBridge(source)` (analogous to the existing `_RealDataGhidraBridge`) that serves imports/exports parsed from a second real PE. Assert `"cutter" in summary.source_bridges`, `summary.complete is True`, and that exports from the Cutter source appear in the aggregated summary.

**`AnalysisAggregator` with both Ghidra + Cutter bridges**
- What to assert: Register both bridges with different real PE sources. After `aggregate`, assert both appear in `source_bridges` and that exports from both sources appear in the export set.

### Priority 2 — Edge-case gaps

**`TransformPipeline` mid-pipeline error propagation**
- What to assert: Build a two-step pipeline where the second step's `process()` raises `TransformParamError`. Call `pipeline.execute(real_pe_bytes)`. Assert the specific exception propagates (not swallowed), and assert the first step's output is NOT silently returned.

**`ProcessManager.run_tracked` ProcessStateError**
- Approach: This requires a process whose `communicate()` completes but `returncode` is still None — a difficult condition to fabricate. If the production code checks `proc.returncode is None` after `communicate()`, a monkeypatch of the Popen.communicate method (not mocking the thing under test — monkeypatching the Popen object's returncode attribute after the real call) would be the least-bad approach. Document this as a hard-to-test sentinel path if the monkeypatch is deemed invasive.

**`ProcessManager._pid_exists_windows` two-stage fallback**
- What to assert: On Windows, construct a scenario where `kernel32.OpenProcess` fails but `psutil.pid_exists()` returns True. This is difficult without Windows-level control; the more achievable test is probing `_pid_exists_windows` directly with a known live PID (os.getpid()) and a known dead PID and asserting the return value — which the existing `register_external_pid` tests already exercise indirectly. Mark as acceptable indirect coverage.

**`ToolRegistry` typed getter ToolError on absence**
- What to assert: Construct a `ToolRegistry(tools_dir=tmp_path)` with no bridges registered. Call `registry.get_hex_editor_bridge()` and assert `ToolError` with message `_ERR_BRIDGE_NA`.

