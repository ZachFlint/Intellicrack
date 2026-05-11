### Category 1 - Empty / Stub Implementations

- **F-0001** (was F-0005, unit `bridges-ghidra`) — `read_bytes` and many other methods relay results that will always be empty due to F-0001
- **F-0002** (was F-0013, unit `bridges-process`) — `_acquire_queryable_job_handle` is a documented stub; `OpenJobObjectW(_, _, NULL)` always fails
- **F-0003** (was F-0001, unit `core-analysis`) — ScriptGenerator.**init** has empty body and class is a no-op shell
- **F-0004** (was F-0001, unit `core-hexpat`) — `builtin_print` evaluator no-op silently swallows arguments
- **F-0005** (was F-0027, unit `core-hexpat`) — `_io_print` registers under bare `print` only via the unreachable namespace path
- **F-0006** (was F-0002, unit `sandbox-py`) — `QEMUSandbox.start()` instantiates `GuestAgentClient` but never calls `connect`
- **F-0007** (was F-0006, unit `sandbox-py`) — No mechanism to start the guest agent script
- **F-0008** (was F-0011, unit `sandbox-scripts`) — `api_trace.ps1` `exit 0` on missing dependency masks setup failure as success
- **F-0009** (was F-0012, unit `sandbox-scripts`) — `api_trace.ps1` starts a logman ETL session it never harvests on success path
- **F-0010** (was F-0013, unit `sandbox-scripts`) — `api_trace.ps1` handler relies on payload field names the AuditAPI provider does not expose
- **F-0011** (was F-0014, unit `sandbox-scripts`) — `api_trace.ps1` cleanup mixes managed-session disposal with logman commands targeting the wrong session
- **F-0012** (was F-0018, unit `ui-panels-hex`) — `_sandbox._do_save` `windows_sandbox` branch ignores `_WDAG_PATH` semantics
- **F-0013** (was F-0002, unit `ui-panels-main`) — SandboxPanel exposes deprecated SandboxBase / SandboxManager setters that only emit a warning and store an unreachable backend

### Category 2 - Hardcoded Return Values & Fake Success

- **F-0014** (was F-0031, unit `bridges-cutter-frida`) — get_function returns hardcoded `0` for parameter and local variable size; fixed `location="stack"` for all params
- **F-0015** (was F-0002, unit `bridges-hex`) — set_va_base claims success when backend lacks add_va_mapping
- **F-0016** (was F-0003, unit `bridges-hex`) — set_chunk_size and set_memory_budget return True regardless of effect
- **F-0017** (was F-0001, unit `bridges-installer`) — PROCESS tool returns sentinel "builtin" path with no real validation
- **F-0018** (was F-0002, unit `bridges-installer`) — Frida "path" is the literal string "frida-python"
- **F-0019** (was F-0003, unit `bridges-installer`) — install_tool reports success even when version verification cannot be performed
- **F-0020** (was F-0004, unit `bridges-installer`) — _install_frida treats successful pip exit as installed even when version probe fails
- **F-0021** (was F-0001, unit `bridges-x64dbg`) — Many command wrappers return hardcoded `{"success": True, ...}` immediately after enqueuing a fire-and-forget x64dbg script command without inspecting the actual outcome
- **F-0022** (was F-0002, unit `bridges-x64dbg`) — `set_breakpoint` always returns a synthetic local id and inserts into the local registry even when the plugin call did not actually create a breakpoint
- **F-0023** (was F-0003, unit `bridges-x64dbg`) — `patch_anti_debug` claims success based on `peb["address"]` but `read_peb`'s tool definition does not advertise such a key, and only patches two of the dozens of advertised "common anti-debug checks"
- **F-0024** (was F-0002, unit `core-analysis`) — Default fallback architecture silently coerces unrecognised binaries to x86-64
- **F-0025** (was F-0003, unit `core-analysis`) — ScriptValidator.validate returns success for unknown languages without checking
- **F-0026** (was F-0002, unit `core-hexpat`) — `_mem_base_address` hardwires 0 instead of honouring `pragma.base_address`
- **F-0027** (was F-0003, unit `core-hexpat`) — `_core_array_index` always returns 0; `set_array_index` never invoked
- **F-0028** (was F-0005, unit `ui-panels-main`) — GhidraPanel.refresh of labels uses 0 as a fallback address when the input is empty, silently changing the user's intent

### Category 3 - Simulated / Mocked Functionality

- **F-0029** (was F-0004, unit `bridges-x64dbg`) — Step-execution functions sleep for 50 ms after issuing a step then read registers; the debugger may not have completed the step in 50 ms

### Category 4 - Ineffective / Naive Implementations

- **F-0030** (was F-0001, unit `bridges-core`) — normalize_type silently downgrades all unknown types to "string"
- **F-0031** (was F-0019, unit `bridges-cutter-frida`) — get_function_address triggers full functions enumeration, then filters in Python
- **F-0032** (was F-0020, unit `bridges-cutter-frida`) — search_strings requires `_analyzed` but the underlying `izj` doesn't need analysis
- **F-0033** (was F-0032, unit `bridges-cutter-frida`) — get_classes maps rizin `methods` and `fields` lists to ClassInfo as raw `list[Any]` without parsing
- **F-0034** (was F-0009, unit `bridges-ghidra`) — `_create_bridge_script` writes the file without an explicit encoding and without `OSError` handling
- **F-0035** (was F-0010, unit `bridges-ghidra`) — `search_bytes` falls back to silently returning `[]` for malformed hex tokens
- **F-0036** (was F-0011, unit `bridges-ghidra`) — `get_call_graph` / `get_call_tree` walk every address in a function body issuing per-byte ref lookups
- **F-0037** (was F-0010, unit `bridges-hex`) — ClamAV NDB scanner strips wildcards, defeating signatures
- **F-0038** (was F-0011, unit `bridges-hex`) — DIE scanner is a fundamental loss of capability
- **F-0039** (was F-0020, unit `bridges-hex`) — read_bytes registered as LLM tool with no length cap
- **F-0040** (was F-0028, unit `bridges-hex`) — snap_to_alignment only floors despite "snap to nearest" docstring
- **F-0041** (was F-0030, unit `bridges-hex`) — BPS encoder degenerate; only emits SourceRead and TargetRead
- **F-0042** (was F-0052, unit `bridges-hex`) — CRC fallback bit-by-bit Python; no zlib/binascii fallback
- **F-0043** (was F-0005, unit `bridges-installer`) — x64dbg version_command "-v" launches the GUI rather than printing a version
- **F-0044** (was F-0006, unit `bridges-installer`) — Cutter version_command runs full Qt GUI binary just to read version
- **F-0045** (was F-0007, unit `bridges-installer`) — find_tool re-runs iterdir() inside the executables loop
- **F-0046** (was F-0008, unit `bridges-installer`) — GitHub asset selection uses fragile substring matches with no architecture check
- **F-0047** (was F-0009, unit `bridges-installer`) — "python" and "pip" used instead of sys.executable / venv pip
- **F-0048** (was F-0010, unit `bridges-installer`) — send_command increments_next_id outside the lock
- **F-0049** (was F-0001, unit `bridges-process`) — `_elevate_debug_privilege` ignores `AdjustTokenPrivileges` BOOL return; `ctypes.get_last_error()` unreliable
- **F-0050** (was F-0002, unit `bridges-process`) — `CreateToolhelp32Snapshot` invalid-handle check uses `== -1` without `restype` declaration
- **F-0051** (was F-0006, unit `bridges-process`) — `get_memory_map` hardcodes `{0x40000, 0x1000000}` instead of using constants
- **F-0052** (was F-0007, unit `bridges-process`) — `_scan_region_pattern` aborts entire region after a single chunk read failure
- **F-0053** (was F-0014, unit `bridges-process`) — `enumerate_com_servers` walks all of HKCR\CLSID synchronously on the asyncio thread
- **F-0054** (was F-0015, unit `bridges-process`) — `detect_dotnet` "version" is a hardcoded string keyed off DLL basename
- **F-0055** (was F-0017, unit `bridges-process`) — `pipe_connect` and `device_open` invoke `CreateFileW` without setting `restype = wintypes.HANDLE`
- **F-0056** (was F-0018, unit `bridges-process`) — `device_ioctl` accepts `bytes` but tool def says hex-string; no shim
- **F-0057** (was F-0047, unit `bridges-process`) — `get_modules` hardcodes `entry_point=0` for every module
- **F-0058** (was F-0048, unit `bridges-process`) — `get_threads` hardcodes `current_pc=0` for every thread
- **F-0059** (was F-0007, unit `bridges-sandbox`) — `get_vnc_port` accesses `instance.sandbox.vnc_port` for any sandbox type without checking VNC support
- **F-0060** (was F-0008, unit `bridges-sandbox`) — `pcap_start`/`screenshot`/`memory_dump`/`extract_dropped_files`/`anti_evasion` accept any sandbox type without QEMU gating
- **F-0061** (was F-0012, unit `bridges-sandbox`) — `extract_iocs`/`timeline`/`detect_behaviors`/`detect_c2`/`diff` re-import `intellicrack.sandbox.analysis` on every call
- **F-0062** (was F-0005, unit `bridges-x64dbg`) — `find_pattern` with wildcards reads only the first `MAX_MEMORY_READ_SIZE` (1 MiB) of every region and silently misses every match outside that window
- **F-0063** (was F-0006, unit `bridges-x64dbg`) — `get_threads` returns `start_address=0`, `current_pc=0`, `state="unknown"` for every thread despite the tool advertising "IDs, entry points, and states"
- **F-0064** (was F-0007, unit `bridges-x64dbg`) — `_read_module_entry_point` returns 0 silently for any module whose header read fails, and reads only 256 bytes without validating PE32 vs PE32+ optional header layout
- **F-0065** (was F-0004, unit `core-analysis`) — validate_java uses substring containment for "import" and "public"
- **F-0066** (was F-0005, unit `core-analysis`) — Aggregator deduplicates imports/exports by address only
- **F-0067** (was F-0017, unit `core-hexpat`) — Two divergent `format` implementations with different syntax
- **F-0068** (was F-0004, unit `core-orchestration`) — Naive `len // 4` token estimate drives context-window trimming and "tokens used" stats
- **F-0069** (was F-0012, unit `core-orchestration`) — `_is_destructive_operation` substring matching has unsafe false positives and false negatives
- **F-0070** (was F-0019, unit `core-orchestration`) — Missing context window silently disables trimming, sending unbounded history to provider
- **F-0071** (was F-0005, unit `providers-cloud`) — Anthropic `enable_cache` only caches the system prompt, never tools or messages
- **F-0072** (was F-0009, unit `providers-cloud`) — Three identical `_convert_tools_to_provider_format` implementations across openai/grok/openrouter
- **F-0073** (was F-0010, unit `providers-cloud`) — Anthropic `connect()` probe uses `limit=1` but pagination loop omits limit
- **F-0074** (was F-0003, unit `providers-local`) — Default model silently substituted on empty input
- **F-0075** (was F-0008, unit `providers-meta`) — `ModelDiscovery.get_recommended_model` is `async` but never awaits anything
- **F-0076** (was F-0009, unit `providers-meta`) — `get_recommended_model` silently returns an arbitrary first model on any unknown `task_type`
- **F-0077** (was F-0010, unit `providers-meta`) — `DiscoveryFilter` regex matching uses `pattern.match` (start-anchored)
- **F-0078** (was F-0018, unit `providers-meta`) — `discover_one` and `discover_provider` duplicate the cache-set / new-removed-diff logic verbatim
- **F-0079** (was F-0019, unit `providers-meta`) — `DiscoveryCache.save_to_disk` calls `time.time()` per iteration instead of snapshotting once
- **F-0080** (was F-0003, unit `sandbox-py`) — `_poll_for_result` returns hardcoded empty stdout/stderr
- **F-0081** (was F-0007, unit `sandbox-py`) — extract_dropped_files won't work if agent disconnected, allowlist mismatch otherwise
- **F-0082** (was F-0012, unit `sandbox-py`) — `pktmon` writes ETL not PCAP
- **F-0083** (was F-0013, unit `sandbox-py`) — `apply_anti_evasion` patches volatile registry hive
- **F-0084** (was F-0020, unit `sandbox-py`) — `extract_dropped_files` ignores xcopy exit codes
- **F-0085** (was F-0023, unit `sandbox-py`) — `list_snapshots` parses QMP response incorrectly
- **F-0086** (was F-0026, unit `sandbox-py`) — `_DOMAIN_PATTERN` matches `.dll`, `.exe`, etc.
- **F-0087** (was F-0027, unit `sandbox-py`) — `yara_scan` falls back to scanning user input
- **F-0088** (was F-0028, unit `sandbox-py`) — QEMU `yara_scan` same defect
- **F-0089** (was F-0034, unit `sandbox-py`) — Windows `run_binary` always reports "success" regardless of exit_code
- **F-0090** (was F-0035, unit `sandbox-py`) — QEMU `run_binary` same defect
- **F-0091** (was F-0022, unit `ui-app-core`) — `ProviderSettingsWidget._setup_provider_specific_ui` only wires three of seven providers
- **F-0092** (was F-0023, unit `ui-app-core`) — `MainWindow._on_browse_models_result` opens `ModelSelectionDialog` without provider context
- **F-0093** (was F-0013, unit `ui-panels-hex`) — `_disassembly._on_cursor_moved_disasm` triggers full bridge disassemble on every cursor movement

### Category 5 - Error Handling Anti-Patterns

- **F-0094** (was F-0002, unit `bridges-core`) — validate_tool_parameter type check is permanently dead because normalize_type cannot return an invalid value
- **F-0095** (was F-0003, unit `bridges-cutter-frida`) — get_imports/get_exports/get_sections silently return [] when not analyzed
- **F-0096** (was F-0004, unit `bridges-cutter-frida`) — get_resources swallows ToolError and returns empty list
- **F-0097** (was F-0021, unit `bridges-cutter-frida`) — `_execute_script_and_wait` returns a result dict that "looks successful" after a timeout
- **F-0098** (was F-0022, unit `bridges-cutter-frida`) — allocate_memory loop doesn't break after extracting addr; later error message can unload script after addr capture
- **F-0099** (was F-0030, unit `bridges-cutter-frida`) — `attach()` calls `await self.initialize()` unconditionally; init errors masquerade as attach errors
- **F-0100** (was F-0006, unit `bridges-ghidra`) — Functions swallow exceptions and return empty defaults so callers cannot distinguish "Ghidra error" from "no data"
- **F-0101** (was F-0007, unit `bridges-ghidra`) — `decompile` returns the literal string `"Decompilation failed"` instead of raising `ToolError`
- **F-0102** (was F-0008, unit `bridges-ghidra`) — `analyze` claims success even when `analyzeAll` is dispatched but never confirmed
- **F-0103** (was F-0016, unit `bridges-hex`) — Pattern registry unavailable returns empty list, indistinguishable from no matches
- **F-0104** (was F-0018, unit `bridges-hex`) — _apply_arithmetic_fallback silently returns input unchanged for xor/and/or without key
- **F-0105** (was F-0026, unit `bridges-hex`) — PE structure bookmarks left half-applied on failure
- **F-0106** (was F-0035, unit `bridges-hex`) — export_ips_patches falls back silently for ips32 path mismatch
- **F-0107** (was F-0041, unit `bridges-hex`) — search_text_encoded falls through silently if Rust path raises
- **F-0108** (was F-0043, unit `bridges-hex`) — ClamAV DB load raises uncaught AttributeError on dict-shaped DB
- **F-0109** (was F-0044, unit `bridges-hex`) — ClamAV dispatch by suffix only; .cdb/.mdb/.fp etc. mishandled
- **F-0110** (was F-0047, unit `bridges-hex`) — base_convert raises uncaught ValueError on bad input
- **F-0111** (was F-0056, unit `bridges-hex`) — get_pe_imports DIRECTORY_ENTRY default 1/0 magic fallback
- **F-0112** (was F-0059, unit `bridges-hex`) — run_python_script catches MemoryError; SystemExit uncaught; OverflowError missing
- **F-0113** (was F-0011, unit `bridges-installer`) — ensure_tool drops original install error when raising
- **F-0114** (was F-0012, unit `bridges-installer`) — _find_frida treats TimeoutExpired identically to "frida not installed"
- **F-0115** (was F-0013, unit `bridges-installer`) — send_command Raises clauses missing from docstring
- **F-0116** (was F-0014, unit `bridges-installer`) — event_handler exceptions propagate and corrupt request stream
- **F-0117** (was F-0015, unit `bridges-installer`) — close() does not wait for in-flight send_command
- **F-0118** (was F-0003, unit `bridges-process`) — `Process32First` failure silently returns empty list
- **F-0119** (was F-0016, unit `bridges-process`) — `pipe_close` and `device_close` always return True even when `CloseHandle` fails
- **F-0120** (was F-0030, unit `bridges-process`) — `_parse_registry_path` only recognises three roots
- **F-0121** (was F-0031, unit `bridges-process`) — `reg_read_value` uses fixed 4096-byte buffer; treats ERROR_MORE_DATA as failure
- **F-0122** (was F-0036, unit `bridges-process`) — `enumerate_com_servers` returns `[]` when `advapi32` is unavailable instead of raising
- **F-0123** (was F-0038, unit `bridges-process`) — `create_section` does not detect `ERROR_ALREADY_EXISTS`
- **F-0124** (was F-0043, unit `bridges-process`) — `query_system_info` only retries on `STATUS_INFO_LENGTH_MISMATCH`
- **F-0125** (was F-0001, unit `bridges-sandbox`) — `cont()` only catches `SandboxError`; `QMPClient.cont()` can raise other exceptions
- **F-0126** (was F-0002, unit `bridges-sandbox`) — Analysis bridge wrappers swallow only `(ValueError, KeyError, TypeError)`; other exceptions escape raw
- **F-0127** (was F-0003, unit `bridges-sandbox`) — `detect_behaviors` silently discards bad rules files instead of erroring
- **F-0128** (was F-0013, unit `bridges-sandbox`) — `cont` returns `success=False` from QMP without raising; "vm_resumed" is logged unconditionally
- **F-0129** (was F-0014, unit `bridges-sandbox`) — `get_pending_messages` builds `{"type": msg.msg_type, "data": msg.data}` outside the `try` block; AttributeErrors leak past the wrapper
- **F-0130** (was F-0008, unit `bridges-x64dbg`) — `_is_recoverable_pipe_error` matches by substring on the error string ("pipe", "not connected", "bridge plugin", "not found", "unknown command", "disconnected", "timed out") - any plugin error containing one of these words is silently swallowed
- **F-0131** (was F-0009, unit `bridges-x64dbg`) — Bare `except Exception` swallow paths convert any error to `ToolError` then proceed, hiding root cause
- **F-0132** (was F-0006, unit `core-hexpat`) — Reflection provider hooks raise on every call because no caller installs a provider
- **F-0133** (was F-0007, unit `core-hexpat`) — `set_print_sink` is dead code: never called from any consumer
- **F-0134** (was F-0006, unit `core-orchestration`) — Auto-save loop dies silently on the first failure
- **F-0135** (was F-0006, unit `providers-cloud`) — OpenAI `chat_stream` swallows transport errors when `_cancel_requested` is set
- **F-0136** (was F-0006, unit `providers-local`) — `chat_template` attribute access can raise `AttributeError` for non-chat tokenizers
- **F-0137** (was F-0007, unit `providers-local`) — `_check_rebar_status` parses PowerShell numeric output unsafely
- **F-0138** (was F-0001, unit `providers-meta`) — Registry `connect_provider()` swallows wrong exception set; provider-raised `ProviderError`/`AuthenticationError` will bypass the handler
- **F-0139** (was F-0013, unit `providers-meta`) — `disconnect_all` aborts the loop on the first provider that raises during disconnect
- **F-0140** (was F-0014, unit `providers-meta`) — `ProviderError` raised inside the registry never carries `provider_name`
- **F-0141** (was F-0024, unit `providers-meta`) — `DiscoveryFilter` invalid regex silently degrades to "no regex applied" instead of failing closed
- **F-0142** (was F-0002, unit `sandbox-scripts`) — `clipboard_monitor.ps1` blanket `SilentlyContinue` swallows all real errors
- **F-0143** (was F-0008, unit `sandbox-scripts`) — `service_monitor.ps1` blanket `SilentlyContinue` masks registry-read failures
- **F-0144** (was F-0026, unit `ui-app-core`) — `MainWindow._refresh_system_status` silently swallows errors and never disables the timer
- **F-0145** (was F-0016, unit `ui-panels-hex`) — `_data_inspector._update_bit_buttons` returns early on first error and leaves remaining bit buttons stale
- **F-0146** (was F-0017, unit `ui-panels-hex`) — `_pattern_editor._on_pattern_apply` only emits `notify_template_registered` from one of two execution paths

### Category 6 - Resource & Lifecycle Issues

- **F-0147** (was F-0009, unit `bridges-cutter-frida`) — enable_crash_reporting registers an unbounded callback handler with no idempotency or off-switch
- **F-0148** (was F-0010, unit `bridges-cutter-frida`) — Detached scripts left in `_alloc_scripts`/`_stalker_scripts`/`_call_probes` when `_unload_script` raises silently
- **F-0149** (was F-0012, unit `bridges-ghidra`) — `shutdown` does not close the `ghidra_bridge` RPC client; the socket leaks
- **F-0150** (was F-0013, unit `bridges-ghidra`) — `shutdown` deletes the bridge script and its parent dir without serialising; concurrent `start_headless` calls race
- **F-0151** (was F-0032, unit `bridges-hex`) — open_file doesn't close previous document; leaks mmap
- **F-0152** (was F-0033, unit `bridges-hex`) — save_to_sandbox leaks created sandbox instance on copy_to failure
- **F-0153** (was F-0042, unit `bridges-hex`) — BPS/UPS export loads original + current docs simultaneously
- **F-0154** (was F-0048, unit `bridges-hex`) — initialize replaces local cache, dropping bridge-side rules
- **F-0155** (was F-0049, unit `bridges-hex`) — save_as doesn't update target_path
- **F-0156** (was F-0016, unit `bridges-installer`) — cancelled connect() may leak the pipe handle
- **F-0157** (was F-0017, unit `bridges-installer`) — _close_handle does not check the CloseHandle return value
- **F-0158** (was F-0018, unit `bridges-installer`) — download_file leaves partial files on failure
- **F-0159** (was F-0019, unit `bridges-installer`) — Unbounded growth of _next_id and lack of wraparound handling
- **F-0160** (was F-0028, unit `bridges-process`) — `read_teb` reads from `self._process_handle` regardless of TID owner
- **F-0161** (was F-0034, unit `bridges-process`) — `_target_is_64bit` falls back to host pointer size when both `IsWow64Process2` and `IsWow64Process` unavailable
- **F-0162** (was F-0039, unit `bridges-process`) — `map_section` has no matching `unmap_section`
- **F-0163** (was F-0040, unit `bridges-process`) — `get_handles` walks entries by index without verifying buffer size
- **F-0164** (was F-0041, unit `bridges-process`) — `stack_walk` discards SuspendThread/SymInitialize BOOL returns
- **F-0165** (was F-0042, unit `bridges-process`) — `_resolve_symbol` allocates only a bare `SYMBOL_INFO` instance; DbgHelp writes past allocation
- **F-0166** (was F-0044, unit `bridges-process`) — `shutdown` releases DLL refs but does not unmap sections, close pipe handles, or close device handles
- **F-0167** (was F-0009, unit `bridges-sandbox`) — `_ensure_manager()` silently re-creates the SandboxManager singleton, losing in-flight instance state
- **F-0168** (was F-0010, unit `bridges-x64dbg`) — `read_memory` / `write_memory` / `allocate_memory` / `free_memory` open a fresh process handle on every call, never caching for the lifetime of the attachment
- **F-0169** (was F-0011, unit `bridges-x64dbg`) — `shutdown` does not wrap `_close_connection` in try/except; if it raises, x64dbg.exe is leaked
- **F-0170** (was F-0020, unit `core-orchestration`) — `_atexit_cleanup` does redundant termination work that can block exit for tens of seconds
- **F-0171** (was F-0021, unit `core-orchestration`) — `Config.parse_providers` drops user-defined providers not present in defaults
- **F-0172** (was F-0023, unit `core-orchestration`) — `ToolRegistry.shutdown` does not clear `self._bridges`
- **F-0173** (was F-0001, unit `hexcore-rust`) — `move_block` clears source without recording undo for the source clear
- **F-0174** (was F-0024, unit `ui-app-core`) — Hardcoded `D:/Intellicrack/...` paths in tool and sandbox defaults
- **F-0175** (was F-0009, unit `ui-panels-hex`) — `_comparison.py` snapshot temp file created with `delete=False` and never cleaned up
- **F-0176** (was F-0022, unit `ui-panels-hex`) — `_hashing._on_custom_crc` reads entire document into Python memory on UI thread
- **F-0177** (was F-0023, unit `ui-panels-hex`) — `_signatures._on_scan_signatures` reads full document on UI thread before launching worker
- **F-0178** (was F-0004, unit `ui-panels-main`) — SandboxPanel cleanup path destroys the sandbox without first stopping an active PCAP capture

### Category 7 - Concurrency / Async Issues

- **F-0179** (was F-0013, unit `bridges-cutter-frida`) — Stalker.unfollow issued from a separate script, not the script that owns Stalker.follow
- **F-0180** (was F-0014, unit `bridges-cutter-frida`) — `_make_payload_waiter` and `_make_install_waiter` capture `loop = asyncio.get_running_loop()` at construction
- **F-0181** (was F-0014, unit `bridges-ghidra`) — `_wait_for_bridge_port` polls but never drains the subprocess's stderr; pipe fills and Ghidra hangs
- **F-0182** (was F-0005, unit `bridges-hex`) — `_state_lock` only acquired in shutdown; meaningless elsewhere
- **F-0183** (was F-0036, unit `bridges-hex`) — hex_state_notify guard silently drops downstream events
- **F-0184** (was F-0037, unit `bridges-hex`) — hex_state set_document reads length outside the lock
- **F-0185** (was F-0038, unit `bridges-hex`) — hex_state asymmetric locking on display_mode getter/setter
- **F-0186** (was F-0039, unit `bridges-hex`) — hex_state property getters read shared state without lock
- **F-0187** (was F-0020, unit `bridges-installer`) — Synchronous event_handler called inside the I/O lock
- **F-0188** (was F-0021, unit `bridges-installer`) — Single global lock serialises all pipe commands; events block requests
- **F-0189** (was F-0022, unit `bridges-installer`) — download progress logging branch fires unreliably
- **F-0190** (was F-0035, unit `bridges-process`) — `async def` methods that loop tens of thousands of times block the event loop
- **F-0191** (was F-0012, unit `bridges-x64dbg`) — Local `_breakpoints` / `_watchpoints` dicts and counter values are mutated from coroutines and from synchronous `_handle_event` callbacks (called from the named-pipe read thread) without any lock
- **F-0192** (was F-0013, unit `core-orchestration`) — `Orchestrator.shutdown`/`cancel` race against pending confirmation futures
- **F-0193** (was F-0024, unit `core-orchestration`) — `SessionManager.update` performs blocking SQLite I/O on the event loop and races with auto-save
- **F-0194** (was F-0025, unit `core-orchestration`) — `_signal_handler` synchronous fallback blocks inside the signal handler
- **F-0195** (was F-0004, unit `hexcore-rust`) — `eval_pointer` swallows recursive-evaluation errors
- **F-0196** (was F-0003, unit `providers-cloud`) — `cancel_request()` is a no-op for non-streaming `chat()` in 4 of 5 providers
- **F-0197** (was F-0006, unit `providers-meta`) — `ModelDiscovery._lock` is allocated but never used
- **F-0198** (was F-0007, unit `providers-meta`) — `DiscoveryCache.get/set/invalidate` advertise thread safety via `_lock` but never acquire it for the hot path
- **F-0199** (was F-0015, unit `providers-meta`) — Singleton pattern offers no reset/teardown API and no DI of credential_loader
- **F-0200** (was F-0022, unit `providers-meta`) — `ProviderRegistry.register/unregister/set_active` mutate shared state without internal locking
- **F-0201** (was F-0001, unit `sandbox-py`) — `SandboxManager.create()` deadlocks on capacity eviction
- **F-0202** (was F-0009, unit `sandbox-scripts`) — `service_monitor.ps1` 2-second polling loop is racy and never compares lifecycle state
- **F-0203** (was F-0021, unit `sandbox-scripts`) — `kernel_object_monitor.ps1` 3-second polling loop misses transient kernel objects entirely
- **F-0204** (was F-0022, unit `sandbox-scripts`) — `kernel_object_monitor.ps1` `OpenProcess(PROCESS_DUP_HANDLE)` against System processes silently fails
- **F-0205** (was F-0023, unit `sandbox-scripts`) — `kernel_object_monitor.ps1` monitor never enables `SeDebugPrivilege` so even peer-process inspection is partial
- **F-0206** (was F-0019, unit `ui-panels-hex`) — `_sandbox.execute_sandbox_operation` creates new asyncio loop per call

### Category 8 - Type Safety Violations

- **F-0207** (was F-0006, unit `bridges-cutter-frida`) — Tool definition for `frida.scan_memory` declares pattern as "string" but Python signature requires bytes
- **F-0208** (was F-0022, unit `core-orchestration`) — `HexDocumentLike` / `HexDocumentFull` Protocol bodies provide concrete return values instead of `...`

### Category 9 - Bridge / Tool Integration Failures

- **F-0209** (was F-0011, unit `bridges-cutter-frida`) — resolve_symbol returns a fabricated `sub_<addr>` name when DebugSymbol resolution fails
- **F-0210** (was F-0012, unit `bridges-cutter-frida`) — `compile_typescript` instantiates `frida.Compiler()` once per call without disposal
- **F-0211** (was F-0001, unit `bridges-ghidra`) — Every `_execute_remote` call expecting a return value is broken: `remote_exec` discards trailing expression results
- **F-0212** (was F-0002, unit `bridges-ghidra`) — Indented multi-line scripts will raise `IndentationError` on the remote `exec`
- **F-0213** (was F-0003, unit `bridges-ghidra`) — `start_headless` deploys a bridge script that calls a non-existent constructor and a non-existent `start()` method
- **F-0214** (was F-0004, unit `bridges-ghidra`) — `analyzeHeadless -postScript` does not keep the JVM alive
- **F-0215** (was F-0006, unit `bridges-hex`) — `apply_transform` and `apply_pipeline` return transformed bytes but never write back
- **F-0216** (was F-0053, unit `bridges-hex`) — fpdf module lazy-import without runtime availability check
- **F-0217** (was F-0023, unit `bridges-installer`) — Hardcoded pipe name prevents multi-instance / multi-tenant use
- **F-0218** (was F-0024, unit `bridges-installer`) — _open_handle uses share_mode=0 (exclusive) - blocks legitimate reconnects
- **F-0219** (was F-0025, unit `bridges-installer`) — deploy_x64dbg_plugin requires write to Program Files without admin check
- **F-0220** (was F-0026, unit `bridges-installer`) — cmake/build feedback dropped on plugin build failure
- **F-0221** (was F-0005, unit `bridges-sandbox`) — Bridge reaches into private QEMU sandbox attributes (`_qmp`, `_agent`)
- **F-0222** (was F-0013, unit `bridges-x64dbg`) — Most public methods (`run`, `pause`, `stop`, step_*, `set_breakpoint`, `remove_breakpoint`, `set_watchpoint`, `remove_watchpoint`, `get_registers`, `set_register`, `read_peb`, `evaluate_expression`, `get_status`, etc.) unconditionally call `_send_pipe_command` and raise immediately when the C++ plugin is not deployed, despite x64dbg having native script equivalents
- **F-0223** (was F-0014, unit `bridges-x64dbg`) — `evaluate_expression` returns `0` for any non-string/non-int payload instead of raising - a real failure to evaluate is indistinguishable from an expression equal to 0
- **F-0224** (was F-0004, unit `core-hexpat`) — `builtin::*` namespace path is unreachable; std-lib delegations always fail
- **F-0225** (was F-0005, unit `core-hexpat`) — `HexPatInterpreter.compile_to_json` swallows runtime errors as `HexPatError`
- **F-0226** (was F-0021, unit `core-hexpat`) — `interpreter.execute()` never connects evaluator/state to stdlib
- **F-0227** (was F-0017, unit `core-orchestration`) — `Cutter` bridge is never auto-initialized despite being instantiated
- **F-0228** (was F-0005, unit `providers-meta`) — `ProviderRegistry` is not a true factory: it cannot map a `ProviderName` to a class
- **F-0229** (was F-0010, unit `sandbox-scripts`) — `start_monitors.cmd` launches monitors fire-and-forget with no PID tracking and no failure surfacing
- **F-0230** (was F-0002, unit `ui-panels-hex`) — Highlight rules update only the local widget, never the bridge
- **F-0231** (was F-0005, unit `ui-panels-hex`) — `_process_memory.py` bypasses bridge and hard-replaces `self.document` without state holder notification
- **F-0232** (was F-0006, unit `ui-panels-hex`) — `_sandbox.py` reimplements docker/qemu/scp/copy logic instead of routing through SandboxBridge
- **F-0233** (was F-0007, unit `ui-panels-hex`) — IPS/BPS/UPS export+import bypass bridge's `export_patches`/`import_patches`
- **F-0234** (was F-0011, unit `ui-panels-hex`) — `_data_inspector._on_encode_text` falls back to a class-level encoder when no doc is open
- **F-0235** (was F-0003, unit `ui-panels-main`) — SandboxPanel VNC autoconnect never forwards the QEMU VNC password

### Category 10 - Subprocess / External Process Issues

- **F-0236** (was F-0015, unit `bridges-ghidra`) — `Popen` invocation lacks `cwd`, env scrubbing, or `creationflags=CREATE_NO_WINDOW`
- **F-0237** (was F-0016, unit `bridges-ghidra`) — `start_headless` resolves `analyzeHeadless.bat` then falls back to `analyzeHeadless` with no platform check
- **F-0238** (was F-0027, unit `bridges-installer`) — cmake configure timeout (120 s) is too tight for cold runs
- **F-0239** (was F-0028, unit `bridges-installer`) — _find_cmake silently returns None on vswhere failure
- **F-0240** (was F-0015, unit `bridges-x64dbg`) — `_start_debugger` spawns x64dbg with `stdout=PIPE, stderr=PIPE` but never reads the pipes - if x64dbg writes more than the pipe buffer (~64 KiB), it blocks on write and deadlocks

### Category 11 - Persistence / State Issues

- **F-0241** (was F-0027, unit `bridges-cutter-frida`) — `_alloc_scripts` mapping never garbage-collects entries when the script unloads via other paths
- **F-0242** (was F-0057, unit `bridges-hex`) — target_path constructed twice; can drift from Rust file_path()
- **F-0243** (was F-0058, unit `bridges-hex`) — hex_state clear_all clears highlights but only emits DOCUMENT_CLOSED
- **F-0244** (was F-0004, unit `bridges-process`) — `terminate` always tears down the bridge handle on the failure branch
- **F-0245** (was F-0005, unit `bridges-process`) — `suspend` / `resume` swallow OpenThread/SuspendThread failures and unconditionally claim success
- **F-0246** (was F-0010, unit `bridges-sandbox`) — `BridgeState` is wired once and never updated; `binary_loaded`/`target_path`/`target_pid`/`last_error` stay frozen
- **F-0247** (was F-0006, unit `core-analysis`) — reload_script ignores subdir saves and silently fails
- **F-0248** (was F-0001, unit `core-orchestration`) — `Orchestrator.load_session` never starts auto-save and bypasses the SessionManager's "current" pointer
- **F-0249** (was F-0005, unit `core-orchestration`) — User message persists to the session even when the agent loop fails
- **F-0250** (was F-0014, unit `core-orchestration`) — `ProcessManager.register_external_pid` does not verify the PID exists
- **F-0251** (was F-0011, unit `providers-meta`) — `DiscoveryCache` stores empty model lists which are then returned as valid cached data
- **F-0252** (was F-0012, unit `providers-meta`) — `discover_all(use_cache=False, force_refresh=False)` leaks stale cache to other readers
- **F-0253** (was F-0016, unit `providers-meta`) — `disconnect_provider` does not clear `_active_provider` when the active provider is disconnected
- **F-0254** (was F-0017, unit `providers-meta`) — `discover_one` returns `[]` for unconnected providers but does not invalidate cache
- **F-0255** (was F-0020, unit `providers-meta`) — `DiscoveryCache.load_from_disk` partially overwrites in-memory cache and offers no atomicity
- **F-0256** (was F-0021, unit `providers-meta`) — `discover_all` records error events but never invalidates the now-known-stale cache entry
- **F-0257** (was F-0015, unit `sandbox-py`) — `start()` redoes accelerator detection
- **F-0258** (was F-0032, unit `sandbox-py`) — `WindowsSandbox.is_available` invokes Get-WindowsOptionalFeature on every call
- **F-0259** (was F-0003, unit `ui-panels-hex`) — Document mutations skip `state_holder.notify_data_modified` in 5+ mixins
- **F-0260** (was F-0004, unit `ui-panels-hex`) — `_on_selection_changed` selection stored locally only; never propagated to bridge
- **F-0261** (was F-0010, unit `ui-panels-hex`) — `panel.py` save path stops listening for `DOCUMENT_OPENED` after first file load
- **F-0262** (was F-0012, unit `ui-panels-hex`) — Pattern editor and templates mixin partial sync to state holder
- **F-0263** (was F-0014, unit `ui-panels-hex`) — `_search` results not cleared when changing modes
- **F-0264** (was F-0008, unit `ui-panels-main`) — SandboxPanel snapshot flow leaves _pending_snapshot_label non-None on error

### Category 12 - Configuration / Feature Flags

- **F-0265** (was F-0027, unit `bridges-hex`) — set_display_mode/set_color_mode don't validate against documented enum
- **F-0266** (was F-0008, unit `core-hexpat`) — `std::core::set_endian` does not affect subsequent struct-field reads
- **F-0267** (was F-0009, unit `core-hexpat`) — `BuiltinFunctions._endian` ignores `pragma.endian`
- **F-0268** (was F-0028, unit `core-hexpat`) — `pragma.eval_depth` default of 32 trips on common `parent`/recursive patterns
- **F-0269** (was F-0010, unit `core-orchestration`) — `_default_providers()` omits two enum members (HUGGINGFACE, GROK)
- **F-0270** (was F-0016, unit `core-orchestration`) — `_default_log_dir()` uses `Path.cwd()` instead of the configured `logs_directory`
- **F-0271** (was F-0001, unit `providers-cloud`) — `enable_cache` accepted but silently discarded in OpenAI/Grok/OpenRouter/Google
- **F-0272** (was F-0002, unit `providers-cloud`) — `thinking` config silently discarded in OpenAI/Grok/OpenRouter/Google
- **F-0273** (was F-0003, unit `sandbox-scripts`) — `clipboard_monitor.ps1` hardcoded log path conflicts with caller-supplied `-LogDir`
- **F-0274** (was F-0005, unit `sandbox-scripts`) — `resource_monitor.ps1` hardcoded `C:\sandbox_shared\logs` ignores caller `-LogDir`
- **F-0275** (was F-0006, unit `sandbox-scripts`) — `resource_monitor.ps1` `SilentlyContinue` hides counter failures forever
- **F-0276** (was F-0007, unit `sandbox-scripts`) — `service_monitor.ps1` hardcoded `C:\sandbox_shared\logs` ignores caller `-LogDir`
- **F-0277** (was F-0024, unit `sandbox-scripts`) — `start_monitors.cmd` hardcoded default log dir contradicts three monitor scripts
- **F-0278** (was F-0025, unit `sandbox-scripts`) — `start_monitors.cmd` PowerShell processes spawned with no shutdown coordination

### Category 13 - Logging / Observability Theater

- **F-0279** (was F-0003, unit `bridges-core`) — validate_and_convert / get_schema_for_provider results are computed only to log a count
- **F-0280** (was F-0019, unit `bridges-ghidra`) — `_logger.info("file_written", ...)` runs without verifying the write
- **F-0281** (was F-0020, unit `bridges-ghidra`) — `set_label`, `add_comment`, `rename_function`, `create_bookmark`, `add_reference`, `create_equate`, `set_program_metadata` all return `success: True` without verifying remote outcome
- **F-0282** (was F-0017, unit `bridges-hex`) — apply_template doesn't notify state holder
- **F-0283** (was F-0021, unit `bridges-hex`) — Wholesale "everything from 0 to length changed" event after every modification
- **F-0284** (was F-0022, unit `bridges-hex`) — State holder notified that entire document changed even when script didn't write
- **F-0285** (was F-0029, unit `bridges-installer`) — Per-chunk pipe write logging at INFO level
- **F-0286** (was F-0030, unit `bridges-installer`) — exception wrapped only as str(exc), losing stack trace in InstallResult.error
- **F-0287** (was F-0029, unit `bridges-process`) — Nearly every public method emits `_started` info-level events
- **F-0288** (was F-0045, unit `bridges-process`) — dispatch shims `list`/`list_detailed`/`open` emit duplicate `_started` log events
- **F-0289** (was F-0006, unit `bridges-sandbox`) — `is_available`, `status`, `list` log `_logger.info("…_started")` on every call
- **F-0290** (was F-0016, unit `bridges-x64dbg`) — INFO-level logs (`breakpoint_set`, `nop_range_filling`, `patches_exporting`, `script_loading`, `plugin_loading`, `handle_closing`, `thread_suspending`, `api_breakpoint_setting`, etc.) emit success messages even though only "command queued" was confirmed
- **F-0291** (was F-0007, unit `core-analysis`) — Script.save logs "script_file_written" before the file is actually written
- **F-0292** (was F-0008, unit `core-analysis`) — TemplateManager logs "file_written" before write completes
- **F-0293** (was F-0009, unit `core-analysis`) — disassemble_to_lines logs constant `binary_path="<bytes-buffer>"`
- **F-0294** (was F-0010, unit `core-analysis`) — validate_javascript logs `temp_file_unlink` and `temp_file_cleaned` around the same call
- **F-0295** (was F-0016, unit `core-hexpat`) — Legitimate `break`/`continue` are logged at WARNING level
- **F-0296** (was F-0011, unit `core-orchestration`) — `_validate_tool_schemas` only logs warnings; broken schemas still go to the provider
- **F-0297** (was F-0018, unit `core-orchestration`) — `tool_status_check_failed` log uses wrong key naming convention; serialises enum repr instead of value
- **F-0298** (was F-0004, unit `providers-local`) — `_logger` instance attribute reassignment loses provider binding
- **F-0299** (was F-0010, unit `sandbox-py`) — `_resolve_worker_pid` heuristic doesn't match docstring
- **F-0300** (was F-0030, unit `sandbox-py`) — Windows `run_binary` 3-second sleep
- **F-0301** (was F-0031, unit `sandbox-py`) — QEMU `run_binary` 2-second sleep
- **F-0302** (was F-0025, unit `ui-app-core`) — `MainWindow._on_provider_changed` only logs the change

### Category 14 - Security / Crypto Failures

- **F-0303** (was F-0015, unit `bridges-cutter-frida`) — JS template strings interpolate integer parameters without explicit `int()` validation
- **F-0304** (was F-0016, unit `bridges-cutter-frida`) — search_string_live and search_assembly_pattern use unescaped user input as r2 commands
- **F-0305** (was F-0017, unit `bridges-ghidra`) — MD5 (with `usedforsecurity=False`) is exposed in `BinaryInfo` next to SHA-256 as if it were an integrity field
- **F-0306** (was F-0018, unit `bridges-ghidra`) — `import_debug_info` passes the path straight to Ghidra with no canonicalisation or existence check
- **F-0307** (was F-0001, unit `bridges-hex`) — `run_python_script` "sandbox" is escapable; permits subprocess.Popen and os.system via **subclasses**
- **F-0308** (was F-0009, unit `bridges-hex`) — MD5 of full file in memory defeats memory-mapped backend
- **F-0309** (was F-0050, unit `bridges-hex`) — export_annotated_html only escapes 3 chars; bookmark color XSS
- **F-0310** (was F-0011, unit `core-analysis`) — _xml_gen obfuscates xml.etree import to evade bandit B405
- **F-0311** (was F-0002, unit `hexcore-rust`) — `swap_blocks` silently zero-pads when blocks have different lengths
- **F-0312** (was F-0005, unit `hexcore-rust`) — `sizeof()` silently returns 0 for unknown type names
- **F-0313** (was F-0017, unit `sandbox-py`) — `_dispatcher_ps1_source` catch swallows all errors

### Category 15 - Platform / Windows Compatibility

- **F-0314** (was F-0021, unit `bridges-ghidra`) — `tempfile.gettempdir()` is shared across instances without race protection
- **F-0315** (was F-0012, unit `bridges-hex`) — list_process_regions docstring says Windows-only, no actual platform check
- **F-0316** (was F-0031, unit `bridges-installer`) — find_tool common_paths use POSIX-style executable for Ghidra alongside .bat
- **F-0317** (was F-0032, unit `bridges-installer`) — Inconsistent Windows guard: os.name vs sys.platform
- **F-0318** (was F-0033, unit `bridges-installer`) — vswhere PROGRAMFILES(X86) lookup uses literal English fallback
- **F-0319** (was F-0017, unit `bridges-x64dbg`) — `_wait_for_pipe_ready` falls back to `await asyncio.sleep(1.0)` on non-Windows and then claims the pipe is ready
- **F-0320** (was F-0018, unit `bridges-x64dbg`) — `_detect_process_arch` silently defaults to "64-bit" on every error path, including when `OpenProcess` succeeds but `IsWow64Process` fails
- **F-0321** (was F-0004, unit `sandbox-py`) — `-cpu host` requires hardware virtualisation; broken with TCG fallback
- **F-0322** (was F-0005, unit `sandbox-py`) — SMB shared folder unavailable on Windows-host QEMU; 9p unsupported

### Category 16 - Binary Analysis-Specific Failures

- **F-0323** (was F-0001, unit `bridges-cutter-frida`) — save_binary uses `wtf {target}` which only writes the current block, not the whole binary
- **F-0324** (was F-0002, unit `bridges-cutter-frida`) — assemble_at writes the assembled bytes twice (`wa` then `wx`)
- **F-0325** (was F-0007, unit `bridges-cutter-frida`) — Frida `call_function` returns `result.toInt32()` for pointer return types, truncating 64-bit values
- **F-0326** (was F-0013, unit `bridges-hex`) — get_pe_imports/get_pe_exports load full document into memory
- **F-0327** (was F-0014, unit `bridges-hex`) — yara_scan loads entire document into memory
- **F-0328** (was F-0015, unit `bridges-hex`) — PE checksum offset hardcoded inline despite available constants
- **F-0329** (was F-0019, unit `bridges-hex`) — entropy/digram_matrix etc. require exact Rust attribute names with no fallback
- **F-0330** (was F-0023, unit `bridges-hex`) — Mach-O missing despite supported_formats=["pe","elf","macho","raw"]
- **F-0331** (was F-0025, unit `bridges-hex`) — Mach-O magics return [] silently in auto_detect_va_mappings
- **F-0332** (was F-0040, unit `bridges-hex`) — UTF-16 scanner accepts code units like 0x2070 as printable
- **F-0333** (was F-0034, unit `bridges-installer`) — get_version subprocess can launch GUI tools mid-analysis
- **F-0334** (was F-0008, unit `bridges-process`) — `get_seh_chain` is x86-only but exposed for arbitrary TIDs
- **F-0335** (was F-0009, unit `bridges-process`) — `get_thread_context` and `set_thread_context` pick CONTEXT64/32 by host pointer size, ignoring WOW64
- **F-0336** (was F-0010, unit `bridges-process`) — `inject_dll` discards `WaitForSingleObject` return; no `GetExitCodeThread`; uses ANSI API for UTF-8 path
- **F-0337** (was F-0011, unit `bridges-process`) — `read_peb` and `read_teb` use a fixed 0x100-byte buffer
- **F-0338** (was F-0019, unit `bridges-process`) — `get_handles` returns raw `ObjectTypeIndex` integers without resolving via `NtQueryObject`
- **F-0339** (was F-0020, unit `bridges-process`) — `_query_thread_state` Suspend-then-Resume-to-probe pattern can leave the thread suspended
- **F-0340** (was F-0021, unit `bridges-process`) — `get_tls_values` reads from TLS *expansion* slot pointer (NULL for nearly every thread)
- **F-0341** (was F-0022, unit `bridges-process`) — `_parse_teb_fields` mislabels TEB+0x58 as `tls_pointer`
- **F-0342** (was F-0019, unit `bridges-x64dbg`) — `get_resources` only walks the top-level resource directory entries, never recursing into sub-directories - cannot return resource sizes/RVAs as advertised
- **F-0343** (was F-0020, unit `bridges-x64dbg`) — `_build_export_entries` silently truncates the export name list to `PE_EXPORT_MAX` (4096) names with no warning
- **F-0344** (was F-0021, unit `bridges-x64dbg`) — `analyze_entropy` reads the entire region in one call - exceeds typical pipe/RPM limits and fails entirely if any page in the range is unreadable
- **F-0345** (was F-0003, unit `core-orchestration`) — `_extract_imports` / `_extract_exports` silently drop everything for Mach-O binaries
- **F-0346** (was F-0015, unit `core-orchestration`) — `_extract_imports` for ELF binaries enumerates only PLT relocations
- **F-0347** (was F-0004, unit `sandbox-scripts`) — `clipboard_monitor.ps1` clobbers PowerShell automatic variable `$pid`
- **F-0348** (was F-0017, unit `sandbox-scripts`) — `injection_monitor.ps1` heuristic mislabels normal thread starts as `shellcode_injection` and fabricates API names
- **F-0349** (was F-0018, unit `sandbox-scripts`) — `dll_monitor.ps1` file-mode logman session collides with realtime TraceEventSession on the same name
- **F-0350** (was F-0019, unit `sandbox-scripts`) — `dll_monitor.ps1` payload-name brute force followed by silent `return` loses every event the heuristic misses
- **F-0351** (was F-0020, unit `sandbox-scripts`) — `dll_monitor.ps1` top-level catch falls back to WMI but never reports it, masking degraded mode

### Category 17 - AI / LLM Provider-Specific Failures

- **F-0352** (was F-0034, unit `bridges-hex`) — get_context_for_ai returns unbounded bookmark list
- **F-0353** (was F-0051, unit `bridges-hex`) — get_digram_matrix returns 65536 integers (~400 KB JSON) per call

### Category 18 - GUI / UX Wiring Failures

- **F-0354** (was F-0026, unit `bridges-cutter-frida`) — Cutter bridge declares `supports_dynamic_analysis=False` but exposes 5 ESIL emulation tools
- **F-0355** (was F-0046, unit `bridges-hex`) — copy_as silently copies one byte at cursor when no selection
- **F-0356** (was F-0022, unit `bridges-x64dbg`) — `set_breakpoint_on_api` uses `bpx module.function` which fails for forwarders, ordinals, manifest-resolved imports, or APIs not yet imported - failure is invisible due to F-0001
- **F-0357** (was F-0004, unit `providers-meta`) — `get_provider_registry` is not exported from `providers/__init__.py`
- **F-0358** (was F-0023, unit `providers-meta`) — `__init__.py` re-exports private TypedDict helpers that have no external consumers
- **F-0359** (was F-0014, unit `sandbox-py`) — `_cleanup` shutil.rmtree silently swallows errors
- **F-0360** (was F-0024, unit `sandbox-py`) — `get_available_types` triggers expensive subprocesses on every call
- **F-0361** (was F-0025, unit `sandbox-py`) — `stop` does not clean active captures
- **F-0362** (was F-0033, unit `sandbox-py`) — `run_command` ticket files never deleted
- **F-0363** (was F-0001, unit `ui-app-core`) — HxD toolbar button is permanently broken (target method does not exist)
- **F-0364** (was F-0002, unit `ui-app-core`) — "Save Patched Binary..." menu item always reports "No hex editor loaded"
- **F-0365** (was F-0003, unit `ui-app-core`) — Sandbox panel "active widget" lookup always returns None (wrong dict)
- **F-0366** (was F-0004, unit `ui-app-core`) — XPUStatusDialog is built and documented but never wired into any menu
- **F-0367** (was F-0005, unit `ui-app-core`) — FunctionListPanel and XRefPanel are wired but never populated with data
- **F-0368** (was F-0006, unit `ui-app-core`) — `_on_view_scripts` collects script panel state then discards it
- **F-0369** (was F-0007, unit `ui-app-core`) — "Tool Status..." menu prefetches statuses and pixmaps that are never passed to the dialog
- **F-0370** (was F-0008, unit `ui-app-core`) — "Configure Tools..." dialog is created without the live tool registry
- **F-0371** (was F-0009, unit `ui-app-core`) — `MainWindow._on_open_sandbox` constructs a throwaway SandboxConfigDialog just to call `is_sandbox_available()`
- **F-0372** (was F-0010, unit `ui-app-core`) — `_apply_provider_settings` silently ignores providers that the user disables
- **F-0373** (was F-0011, unit `ui-app-core`) — `PreferencesDialog.settings_changed` signal has no consumers
- **F-0374** (was F-0012, unit `ui-app-core`) — `SessionManagerDialog.session_loaded` and `session_deleted` signals have no consumers
- **F-0375** (was F-0013, unit `ui-app-core`) — `ProviderConfigDialog.provider_updated` and `active_provider_changed` signals have no consumers
- **F-0376** (was F-0014, unit `ui-app-core`) — `ModelSelectionDialog.model_selected` signal has no external consumers
- **F-0377** (was F-0015, unit `ui-app-core`) — `SandboxConfigDialog.settings_updated` signal has no consumers
- **F-0378** (was F-0016, unit `ui-app-core`) — `SandboxMonitorWidget.sandbox_stopped` signal has no consumers
- **F-0379** (was F-0017, unit `ui-app-core`) — `ToolConfigDialog.tool_updated` signal has no consumers
- **F-0380** (was F-0018, unit `ui-app-core`) — `ToolSettingsWidget.status_changed` signal has no consumers
- **F-0381** (was F-0019, unit `ui-app-core`) — `ToolOutputPanel.embedded_tool_started` and `embedded_tool_closed` signals have no consumers
- **F-0382** (was F-0001, unit `ui-panels-hex`) — Search is wired to non-existent `self._document`; every search no-ops or raises AttributeError
- **F-0383** (was F-0024, unit `ui-panels-hex`) — `panel._do_copy_as` swallows errors silently when no clipboard is available
- **F-0384** (was F-0001, unit `ui-panels-process`) — `_status_arch` label is permanently `"Arch: --"` — never updated from the bridge
- **F-0385** (was F-0002, unit `ui-panels-process`) — `_status_priv` privilege label depends on a private bridge attribute that is never refreshed after a privilege change
- **F-0386** (was F-0003, unit `ui-panels-process`) — `MemoryTab._region_filter` filter input is never connected to anything
- **F-0387** (was F-0004, unit `ui-panels-process`) — `ModulesTab._mod_filter` filter input is never connected to anything
- **F-0388** (was F-0005, unit `ui-panels-process`) — Memory tab actions are not gated on attachment — silent no-ops with no user feedback when not attached
- **F-0389** (was F-0006, unit `ui-panels-process`) — `MemoryTab._on_search` "Searching..." status never resets on failure
- **F-0390** (was F-0007, unit `ui-panels-process`) — `MemoryTab._on_free` adds a new "Freed" row instead of removing the corresponding "Allocated" row
- **F-0391** (was F-0008, unit `ui-panels-process`) — `_on_protect` and `_on_free` parse errors are logged but not surfaced
- **F-0392** (was F-0009, unit `ui-panels-process`) — `MemoryTab._build_protect_tab` lacks a placeholder hint for the address field
- **F-0393** (was F-0010, unit `ui-panels-process`) — `ThreadsTab._on_suspend_thread` / `_on_resume_thread` mislabeled — they suspend the entire process
- **F-0394** (was F-0011, unit `ui-panels-process`) — `ThreadsTab._on_tls` reads the TID from the Fiber combo, not its own selector
- **F-0395** (was F-0012, unit `ui-panels-process`) — `ThreadsTab` thread combos only update on explicit Refresh
- **F-0396** (was F-0013, unit `ui-panels-process`) — `ProcessTab._inject_btn` does not require attachment and gives no feedback on failure or success
- **F-0397** (was F-0014, unit `ui-panels-process`) — `ProcessTab._on_filter_changed` fires a full bridge round-trip on every keystroke
- **F-0398** (was F-0015, unit `ui-panels-process`) — `ProcessTab._on_attach` does not surface failure
- **F-0399** (was F-0016, unit `ui-panels-process`) — `ProcessTab._on_suspend`, `_on_resume`, `_on_terminate`, and `_load_process_info` silently consume bridge errors
- **F-0400** (was F-0017, unit `ui-panels-process`) — `ProcessTab._on_terminate` only refreshes the system list, not the Tracked sub-tab
- **F-0401** (was F-0018, unit `ui-panels-process`) — `ProcessTab._on_terminate` does not detach the panel state if the terminated PID is currently attached
- **F-0402** (was F-0019, unit `ui-panels-process`) — `ThreadsTab._on_write_registers` reads only the Hex column — Decimal-column edits are silently dropped
- **F-0403** (was F-0020, unit `ui-panels-process`) — `SystemTab._on_pipe_close` removes the row before knowing whether the close succeeded
- **F-0404** (was F-0021, unit `ui-panels-process`) — `SystemTab._on_job_info` appends to `_res_tree` instead of clearing it
- **F-0405** (was F-0022, unit `ui-panels-process`) — `SystemTab` privileges, debug-enable, services, and PEB read ignore `_attached_pid is None`
- **F-0406** (was F-0023, unit `ui-panels-process`) — SystemTab queries swallow bridge errors silently
- **F-0407** (was F-0024, unit `ui-panels-process`) — ModulesTab refreshes (handles, heaps, COM, .NET) all swallow bridge errors
- **F-0408** (was F-0025, unit `ui-panels-process`) — `_base._update_controls_for_state` enables/disables tab widgets but never enables/disables Process tab buttons
- **F-0409** (was F-0026, unit `ui-panels-process`) — `_workers.TrackedRefreshWorker` swallows all errors and emits an empty list

### Category 19 - Data Parsing / Format Issues

- **F-0410** (was F-0008, unit `bridges-cutter-frida`) — read_memory `data` key collides between binary side-channel and JSON payload `data` field
- **F-0411** (was F-0017, unit `bridges-cutter-frida`) — `_cmd_json` returns silent `[]` on JSON parse failure, masking command errors
- **F-0412** (was F-0018, unit `bridges-cutter-frida`) — MemoryRegion always sets `state="MEM_COMMIT", type="MEM_PRIVATE"` (Windows-only constants) regardless of platform
- **F-0413** (was F-0029, unit `bridges-cutter-frida`) — Cutter `is_64bit` heuristic compares `bits == 64` only
- **F-0414** (was F-0022, unit `bridges-ghidra`) — `get_xrefs_to` / `get_xrefs_from` collapse all reference types to `"call"` or `"data"` losing JUMP/READ/WRITE distinctions
- **F-0415** (was F-0007, unit `bridges-hex`) — `_build_ips_from_patches` overflow handling broken
- **F-0416** (was F-0008, unit `bridges-hex`) — `_apply_ips_patches` premature break + project-invented EOF marker
- **F-0417** (was F-0029, unit `bridges-hex`) — UTF-16LE scanner only checks even starting offsets
- **F-0418** (was F-0035, unit `bridges-installer`) — _parse_version returns ToolVersion(0,0,0) for any unparseable input
- **F-0419** (was F-0036, unit `bridges-installer`) — x64dbg snapshot version strings parsed as semver fail min_version comparison
- **F-0420** (was F-0012, unit `bridges-process`) — `_extract_env_pointer` uses bogus offsets and wrong field width
- **F-0421** (was F-0023, unit `bridges-process`) — `_parse_service_entries` stores raw `c_wchar_p` pointers (not Python strings)
- **F-0422** (was F-0024, unit `bridges-process`) — `_resolve_symbol` uses magic expression for `SizeOfStruct`
- **F-0423** (was F-0025, unit `bridges-process`) — `_resolve_module` uses an undersized 584-byte raw buffer
- **F-0424** (was F-0032, unit `bridges-process`) — `_check_inproc_server` only walks `CLSID\…\InprocServer32`
- **F-0425** (was F-0033, unit `bridges-process`) — `get_environment` caps the env-block read at 64 KiB
- **F-0426** (was F-0046, unit `bridges-process`) — `_extract_env_pointer` reads `<H` (16-bit) for `EnvironmentSize`
- **F-0427** (was F-0004, unit `bridges-sandbox`) — `yara_scan` advertises `enum=["files","memory"]` but performs zero validation
- **F-0428** (was F-0015, unit `bridges-sandbox`) — `_report_to_dict` emits `list(report.file_changes)` etc. — typed dataclasses, not JSON-serialisable dicts
- **F-0429** (was F-0016, unit `bridges-sandbox`) — Timestamps in `list()` and `create()` emitted as `isoformat()` without timezone labelling in the schema
- **F-0430** (was F-0023, unit `bridges-x64dbg`) — `_detect_architecture` returns `True` (= 64-bit) for any I/O failure, files smaller than `PE_MAGIC_OFFSET`, files lacking `MZ`, files lacking `PE\x00\x00`, and `False` for any non-x86 architecture (ARM/ARM64/IA64) - silently launches the wrong debugger
- **F-0431** (was F-0024, unit `bridges-x64dbg`) — `_extract_command_line_from_peb` silently trims an odd `length` byte before decoding utf-16-le instead of rejecting the malformed input
- **F-0432** (was F-0012, unit `core-hexpat`) — Variadic function parameters parsed but ignored at call time
- **F-0433** (was F-0013, unit `core-hexpat`) — Generic templates parsed but completely ignored
- **F-0434** (was F-0014, unit `core-hexpat`) — `using` alias rejects array, pointer, and padding targets
- **F-0435** (was F-0015, unit `core-hexpat`) — Namespaced types collide on local name in the global type table
- **F-0436** (was F-0019, unit `core-hexpat`) — `_eval_array_field` ignores `is_pointer` for pointer-array fields
- **F-0437** (was F-0026, unit `core-hexpat`) — `HexPatCompiler.compile` accepts patterns the evaluator can run; static template silently drops semantics
- **F-0438** (was F-0007, unit `providers-cloud`) — `_convert_tool_choice_to_openai_format` produces empty function name when SPECIFIC mode lacks `function_name`
- **F-0439** (was F-0002, unit `providers-local`) — Cloud-stream tool-call dict arguments are silently dropped
- **F-0440** (was F-0005, unit `providers-local`) — `_extract_text_before_tool_call` regex misses whitespace-formatted tool calls
- **F-0441** (was F-0020, unit `ui-panels-hex`) — `_scripting._DocAPI.search_text` hard-codes UTF-8, ignoring panel's encoding combo
- **F-0442** (was F-0021, unit `ui-panels-hex`) — `_scripting.execute_script` `print(..., file=...)` lost or crashes
- **F-0443** (was F-0007, unit `ui-panels-main`) — VNCWidget framebuffer pump silently drops every encoding except RAW, leaving the user with a frozen display

### Category 20 - Dead Code & Unreachable Paths

- **F-0444** (was F-0004, unit `bridges-core`) — bridges/**init**.py public re-exports are unused by production code
- **F-0445** (was F-0025, unit `bridges-cutter-frida`) — `r2.setter` never used; the bridge writes to `self._r2` directly everywhere
- **F-0446** (was F-0023, unit `bridges-ghidra`) — `BridgeCapabilities.supports_patching=True` is reported but no `apply_patch`/`patch` method exists
- **F-0447** (was F-0024, unit `bridges-ghidra`) — `set_color` IntPropertyMap fallback returns `success: True` while having no visual effect in headless mode
- **F-0448** (was F-0004, unit `bridges-hex`) — `_alignment_grid_size` is written and never read
- **F-0449** (was F-0037, unit `bridges-installer`) — Tool registry omits SANDBOX and HEX_EDITOR enum members
- **F-0450** (was F-0038, unit `bridges-installer`) — _PLUGIN_ARCHS third tuple field is unused
- **F-0451** (was F-0025, unit `bridges-x64dbg`) — `WIN_NO_INHERIT_HANDLE: bool = False` is a top-level constant suggesting configurability that does not exist; literal `False` is also used in some `OpenProcess` calls inconsistently
- **F-0452** (was F-0018, unit `core-hexpat`) — Unreachable `_endian` fallback in `_core_set_endian`
- **F-0453** (was F-0020, unit `core-hexpat`) — `BuiltinFunctions.set_array_index` defined but never called
- **F-0454** (was F-0007, unit `core-orchestration`) — `Session.tool_states` is never written by the application
- **F-0455** (was F-0008, unit `core-orchestration`) — `Session.tags` are stored but never assigned by any non-test code path
- **F-0456** (was F-0009, unit `core-orchestration`) — Duplicate `Session` dataclass in `types.py` shadows the real one and exports a stale shape
- **F-0457** (was F-0008, unit `providers-cloud`) — `get_pending_usage()` / `get_pending_thinking()` populated by every provider but never consumed
- **F-0458** (was F-0001, unit `providers-local`) — Dead constants `_B580_DEVICE_IDS` and `_INTEL_VENDOR_ID`
- **F-0459** (was F-0003, unit `providers-meta`) — `ProviderRegistry._credential_loader` parameter is wired but never reached
- **F-0460** (was F-0001, unit `sandbox-scripts`) — `clipboard_monitor.ps1` fallback polling loop is unreachable
- **F-0461** (was F-0015, unit `sandbox-scripts`) — `injection_monitor.ps1` tracks `$logmanStarted` for a session it never created via logman
- **F-0462** (was F-0016, unit `sandbox-scripts`) — `injection_monitor.ps1` `return` from top-level script silently aborts
- **F-0463** (was F-0020, unit `ui-app-core`) — `ToolConfirmationDialog.remember_similar` is captured but never read by callers
- **F-0464** (was F-0021, unit `ui-app-core`) — `ToolOutputPanel.wire_sandbox_backend` is a deprecated no-op never called
- **F-0465** (was F-0008, unit `ui-panels-hex`) — `_ips.py` entire 285-line module is dead code
- **F-0466** (was F-0015, unit `ui-panels-hex`) — `_highlighting.refresh_pattern_highlights` calls `_hex_widget.update()` twice
- **F-0467** (was F-0001, unit `ui-panels-main`) — HxDPanel is implemented but never imported, instantiated, or exposed by the panels package

### Category 21 - Documentation / Signature Drift

- **F-0468** (was F-0005, unit `bridges-core`) — protection_to_string promised "rwx" / "r--" return shape is contradicted by its implementation
- **F-0469** (was F-0006, unit `bridges-core`) — state_to_string and mem_type_to_string silently bucket all unknown values to "unknown"
- **F-0470** (was F-0028, unit `bridges-cutter-frida`) — `assemble_at` returns `bytes` but tool definition says "Assembled bytes"
- **F-0471** (was F-0025, unit `bridges-ghidra`) — Docstrings universally promise `Raises: ToolError` but the implementation returns empty containers
- **F-0472** (was F-0026, unit `bridges-ghidra`) — `get_xrefs_to` / `get_xrefs_from` advertise `from_function` / `to_function` enrichment but always set them to `None`
- **F-0473** (was F-0031, unit `bridges-hex`) — toggle_bit Rust path doesn't emit log; fallback path does
- **F-0474** (was F-0054, unit `bridges-hex`) — search_numeric accepts unknown value_type, silently treats as uint
- **F-0475** (was F-0060, unit `bridges-hex`) — safe_print ignores file= kwarg; no size cap on capture
- **F-0476** (was F-0039, unit `bridges-installer`) — send_command docstring missing Raises section despite raising paths
- **F-0477** (was F-0040, unit `bridges-installer`) — close() docstring omits the I/O thread-pool side effects
- **F-0478** (was F-0041, unit `bridges-installer`) — get_version docstring claims behaviour the code does not deliver for x64dbg
- **F-0479** (was F-0026, unit `bridges-process`) — tool defs say "Success status" but impls always return True regardless of partial failure
- **F-0480** (was F-0027, unit `bridges-process`) — `get_mitigation_policies` reports `enabled = bool(flags & 1)` for every policy
- **F-0481** (was F-0037, unit `bridges-process`) — tool defs claim "Hex string" but impls return raw `bytes`
- **F-0482** (was F-0011, unit `bridges-sandbox`) — Tool-definition `default` values for `time_limit`, `output_path`, `args`, `categories` are absent
- **F-0483** (was F-0026, unit `bridges-x64dbg`) — `set_breakpoint`'s tool definition advertises a `condition` parameter; the implementation forwards it via `bp_set` payload but does not also issue a `bpcond` script command, so honouring the condition depends on undocumented plugin behaviour
- **F-0484** (was F-0027, unit `bridges-x64dbg`) — `get_process_info` returns `None` when not attached, but tool definition documents return as "ProcessInfo with threads, modules, command line, and parent PID"
- **F-0485** (was F-0012, unit `core-analysis`) — script_gen module docstring promises script execution that does not exist
- **F-0486** (was F-0013, unit `core-analysis`) — Script.created_at uses naive datetime.now while last_run uses UTC
- **F-0487** (was F-0010, unit `core-hexpat`) — `std::string::parse_int` registered as `to_int`; std-lib calls fail
- **F-0488** (was F-0011, unit `core-hexpat`) — Multiple `builtin::std::mem::*` callees referenced by std-lib but never registered
- **F-0489** (was F-0022, unit `core-hexpat`) — `_resolve_endian` docstring promises pragma-aware native; implementation ignores pragma
- **F-0490** (was F-0024, unit `core-hexpat`) — `HexPatPreprocessor.process` discards `pragma.base_address` from emitted source
- **F-0491** (was F-0025, unit `core-hexpat`) — `_eval_namespace_access` synthesises `f"{ns_name}::{member}"` from short namespace name
- **F-0492** (was F-0002, unit `core-orchestration`) — System prompt instructs the LLM to call non-existent `binary.*` tools
- **F-0493** (was F-0008, unit `sandbox-py`) — `_file_monitor_source` uses `$using:` which is invalid in `Register-ObjectEvent -Action`
- **F-0494** (was F-0009, unit `sandbox-py`) — QEMU agent script same `$using:` defect
- **F-0495** (was F-0011, unit `sandbox-py`) — `time_limit` vs `timeout_seconds` mismatch
- **F-0496** (was F-0016, unit `sandbox-py`) — `_detect_accelerator` reports WHPX available on Hyper-V-disabled hosts
- **F-0497** (was F-0018, unit `sandbox-py`) — `_process_monitor_source` uses `$pid` automatic variable
- **F-0498** (was F-0019, unit `sandbox-py`) — `_registry_monitor_source` hardcoded REG_SZ + unapproved verb
- **F-0499** (was F-0021, unit `sandbox-py`) — `dump_memory` cannot succeed against vmwp.exe
- **F-0500** (was F-0022, unit `sandbox-py`) — QEMU `apply_anti_evasion` uses `reg.exe` blocked by guest agent allowlist
- **F-0501** (was F-0029, unit `sandbox-py`) — QEMU `apply_anti_evasion(profile=...)` ignores profile parameter

### Category 22 - Test / Debug Code Leaked Into Production

- **F-0502** (was F-0005, unit `bridges-cutter-frida`) — hook_function leaks default `console.log('[+] Called ...')` instrumentation in production
- **F-0503** (was F-0027, unit `bridges-ghidra`) — `analyze` writes `ghidra_analysis_complete` log without distinguishing analyser passes
- **F-0504** (was F-0045, unit `bridges-hex`) — run_python_script forbidden_builtins set looks like a hand-rolled prototype
- **F-0505** (was F-0014, unit `core-analysis`) — Inline comment in reload_script admits broken implementation
- **F-0506** (was F-0003, unit `hexcore-rust`) — `diff_data_block` block-level fallback is dead code
- **F-0507** (was F-0006, unit `ui-panels-main`) — ScriptTypeInfo "x64dbg" template emits a self-contradictory bypass script

### Category 23 - Build / Release Metadata Lies

- **F-0508** (was F-0024, unit `bridges-hex`) — Capabilities advertise macho/scripting that aren't real
- **F-0509** (was F-0001, unit `config-pyproject`) — `pyproject.toml` redundantly declares 95+ dev/test/docs/profile packages as runtime `dependencies`

### Category 24 - Recovery / Robustness Theater

- **F-0510** (was F-0007, unit `bridges-core`) — ToolBridgeBase.shutdown does no real cleanup
- **F-0511** (was F-0023, unit `bridges-cutter-frida`) — Generic `except Exception` blocks throughout swallow Frida transport errors with only str() context
- **F-0512** (was F-0024, unit `bridges-cutter-frida`) — shutdown() calls super().shutdown() AFTER releasing all references
- **F-0513** (was F-0028, unit `bridges-ghidra`) — `decompile`, `read_bytes`, `disassemble` silently degrade to "no result" instead of escalating
- **F-0514** (was F-0055, unit `bridges-hex`) — open_process_memory doesn't close any previously open document
- **F-0515** (was F-0042, unit `bridges-installer`) — _PIPE_ERROR_HINTS only covers 3 of the common pipe errors
- **F-0516** (was F-0043, unit `bridges-installer`) — deploy_x64dbg_plugin returns True when one arch is up-to-date even if other arches failed
- **F-0517** (was F-0044, unit `bridges-installer`) — _extract_archive returns tool_dir when no subdir was extracted
- **F-0518** (was F-0028, unit `bridges-x64dbg`) — Several methods catch the recoverable-pipe class of `ToolError` and fall back to `_send_command(...)`, but `_send_command` is itself a thin wrapper around `_send_pipe_command("exec", ...)`. The "fallback" travels the same broken pipe
- **F-0519** (was F-0029, unit `bridges-x64dbg`) — `get_status` falls back to `{"debugging": False, "paused": False, "initialized": False}` when the plugin returns a non-dict result - all-false state is indistinguishable from a real "not running" state
- **F-0520** (was F-0015, unit `core-analysis`) — AnalysisAggregator continues with BinaryInfo only and reports a "summary" that may be empty
- **F-0521** (was F-0023, unit `core-hexpat`) — `parser.parse()` collects errors but never returns them
- **F-0522** (was F-0004, unit `providers-cloud`) — `_retry_with_backoff` only used by Anthropic and OpenAI; Grok/Google/OpenRouter never retry on rate limits
- **F-0523** (was F-0002, unit `providers-meta`) — Registry `connect_provider()` documents `bool` return but never returns `False`
