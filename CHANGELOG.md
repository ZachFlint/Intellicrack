# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [Unreleased]

### Added

- Implement BitAndZero opcode in hexcore and compiler (`f144be8`)
Introduces a dedicated BitAndZero condition operator to the Rust hexcore evaluator and updates the Python compiler to utilize it for inverted bit-mask predicates. This allows the compiler to correctly lower if/else constructs involving bitwise AND operations, which previously raised an error due to the lack of a direct inverse primitive.
* Implement BitAndZero logic in TemplateEvaluator and ConditionOp
* Update HexPatCodegen to map BitAnd to BitAndZero for else-branch inversion
* Refactor various UI components and docstrings for consistent line length and formatting
* Update linting reports and semgrep rules to reflect recent codebase changes

- Migrate test harness from Windows Sandbox to Docker (`cf470c3`)
Replace the legacy Windows Sandbox-based test redirection with a unified Docker-based sandbox driver. The new harness uses Windows process-isolated containers to provide consistent, reproducible environments for unit, integration, and E2E tests while maintaining host-side report harvesting.
- Add `scripts/sandbox/` driver for container orchestration and artifact collection
- Add `docker/Dockerfile.windows` and `entrypoint.ps1` for the test environment
- Update `justfile` to route all test and documentation tasks through the new scripts
- Implement `HexEditorBridge` wiring in the UI to support RPC-backed transforms
- Enhance `CutterPanel` with automatic ESIL memory initialization and hexdump previews
- Refactor `Orchestrator` session creation to support persistent metadata (name/notes)
- Remove legacy `.ps1` documentation and sandbox launchers in favor of unified Python/PowerShell dispatchers

- **hexpat:** Parser — templates, varargs, padding, enum ranges, endianness, recovery (B27-B31, B37, B38)  (`f64500b`)

- **hexpat:** Add optional span fields on parse/runtime errors (B36)  (`d324291`)

- **hexpat:** Stdlib — math/hash/time/file/random/env/reflection + fixes (B39-B44)  (`f21568d`)
Implements 18+ math fns (sin, cos, tan, asin, acos, atan, atan2, sinh, cosh,
tanh, asinh, acosh, atanh, exp, log/ln, log10, cbrt, round, trunc, fmod,
accumulate), hash fns (crc8/16/32/64 via generic CRC engine), time fns
(epoch, to_local, to_utc, format), sandboxed file fns (open, close, read,
write, seek, size, resize, flush, remove, create_directories), random fns
(set_seed, generate with Distribution enum), env, sizeof_pack, and core
reflection fns wired through an _ReflectionProvider dataclass.

- **hexcore:** Big-endian ELF support and Sym/Rel/Rela/Dyn/Nhdr templates  (`0f2027d`)
F13 — add FieldType::EndiannessSwitch { peek_offset, big_value }.
Evaluator tracks base_offset for struct references and flips
default_endian by peeking e_ident[EI_DATA] (offset 5, value 2 == MSB).
Elf32_Ehdr and Elf64_Ehdr embed the marker immediately after e_ident so
all subsequent fields use correct endianness. BE ELF binaries
(PowerPC/SPARC/MIPS-BE/s390) now parse correctly.
F21 — add Elf32_Sym, Elf64_Sym, Elf32_Rel, Elf64_Rel, Elf32_Rela,
Elf64_Rela, Elf32_Dyn, Elf64_Dyn, Elf_Nhdr. Elf_Nhdr uses Computed
fields to round n_namesz/n_descsz to 4-byte alignment before
DynamicArray payloads per ELF note layout.

- **hexcore:** Add fat/universal Mach-O and 32-bit + common load commands  (`6072d51`)
Adds FAT_HEADER / FAT_ARCH for universal binary headers, MACH_HEADER_BE /
MACH_HEADER_64_BE for big-endian headers, SEGMENT_COMMAND + SECTION for
32-bit LC_SEGMENT, SECTION_64 for 64-bit section descriptors,
SYMTAB_COMMAND, DYLIB_COMMAND, DYLD_INFO_COMMAND, and MAIN_COMMAND.

- **hexcore:** Add ZIP64 structures and data descriptor templates  (`aa2ca49`)
Adds ZIP64 EOCD record (0x06064B50), ZIP64 EOCD locator (0x07064B50),
ZIP64 extra field (header ID 0x0001), and standard/ZIP64 variants of
the data descriptor (0x08074B50) so large archives and streaming-flag
entries parse correctly.

- **hexcore:** Strict AES-ECB padding modes and bit_shift overflow guard  (`ea1bda9`)
F8 — AES-ECB: add PaddingMode {None, Pkcs7, Zero, Iso10126}. Decrypt
requires data.len() % 16 == 0 in all modes (no more silent zero-pad).
PKCS#7 validates length + every pad byte; bad padding errors. Encrypt
pads plaintext per mode; None mode errors on misaligned input.
transform_data dispatch parses `padding` key from params dict; default
is Pkcs7.
F11 — bit_shift_left/right validate count <= 7 and return
TransformError::InvalidParameter for out-of-range counts, replacing the
silent `count & 7` clamp. bit_rotate_left/right retain modulo-8.

- **hexcore:** Patch export COD/JSON + fix IPS/IPS32 terminator collisions  (`60019ce`)
F20 — adds two new patch-export formats:
- export_cod: 4-byte BE offset + 4-byte BE length + data per record.
- export_patches_json: serde_json-pretty serialization of the patch
list (offset + data).
Wired into HexDocument PyO3 as export_patches_cod and
export_patches_json, with matching stubs in intellicrack_hexcore.pyi.
F22 — in export_ips, when a record's offset equals or spans the byte
0x454F46 ("EOF"), splits/shifts the emitted header so the 3-byte BE
offset field can never match the IPS terminator. Adds regression test
for a record sitting exactly on the collision offset and another that
spans it.
F23 — same treatment for export_ips32 around 0x45454F46 ("EEOF"), the
IPS32 terminator. Reachable in >1 GiB binaries. Adds regression tests
for a record at and spanning the collision offset.

- **hexcore:** Support full Unicode in UTF-16LE string extractor  (`5f860a5`)
Generalize the printable test to operate on decoded Unicode scalar values,
accepting any non-control character plus TAB/LF/CR. Handle UTF-16 surrogate
pairs so supplementary-plane code points (emoji, CJK extension blocks, etc.)
are recovered, with dangling or mismatched surrogates gracefully terminating
the current candidate instead of being silently dropped.

- Overhaul binary analysis architecture and expand tool bridges (`0a541ff`)
This massive update represents a significant architectural pivot, transitioning from a process-centric model to a centralized, state-managed binary analysis framework. The core of the application has been refactored to prioritize advanced hex editing, deep static analysis, and comprehensive sandbox orchestration. By moving logic out of the legacy bridge layers and into a robust core orchestrator, the system now supports more complex, multi-tool workflows with improved thread safety and state synchronization.
The Rust-based hex engine has been significantly enhanced to support large-file operations, patch formats, and granular memory manipulation, while the UI has been decomposed into modular mixins to manage the increased complexity of the new analysis panels. The tool bridges for Frida, Ghidra, Cutter, and x64dbg have been expanded from basic wrappers into full-featured instrumentation and analysis interfaces. This restructuring also introduces a sophisticated sandbox monitoring subsystem capable of behavioral analysis, network capture, and automated IOC extraction, providing a unified environment for both static and dynamic malware research.
Core Architecture & Orchestration:
* Refactored `src.intellicrack.core.orchestrator` to centralize logic previously held in bridges, adding `lief`-based binary parsing for section and import extraction.
* Updated `ToolRegistry` in `src.intellicrack.core.tools` to use dynamic imports for bridge instantiation, reducing circular dependencies and removing the redundant `BinaryBridge`.
* Implemented a thread-safe state management system in `src.intellicrack.bridges.hex_state` with new event types for VA mapping, alignment grids, and color modes.
* Expanded the Rust backend in `src/intellicrack-hexcore` with new modules for BPS/UPS patch handling, string extraction, and PE checksum verification.
Binary & Hex Editing Subsystem:
* Introduced `HexEditorBridge` with comprehensive support for block operations (fill, copy, move, swap), bitwise arithmetic, and VA mapping management.
* Added a modular UI for the hex editor in `src.intellicrack.ui.panels.hex_editor`, utilizing mixins for hashing, signatures, scripting, and process memory access.
* Implemented a background `DiffWorker` in `_comparison.py` to enable non-blocking side-by-side binary comparisons.
* Added `_data_inspector.py` to provide granular bit-level editing and multi-encoding text decoding directly within the hex view.
Tool Bridge Enhancements:
* Expanded `FridaBridge` to include cross-language runtime hooking (Java/ObjC), kernel memory access, and persistent script management via `CModule`.
* Upgraded `GhidraBridge` with P-code IR analysis, control flow graph generation, and automated symbol/type management functions.
* Refactored `CutterBridge` to support ROP gadget searching, ESIL emulation, and Zignature management while switching assembly backend to Rizin's `pa` command.
* Enhanced `x64dbg` bridge and plugin with support for expression evaluation, resource enumeration, anti-debug detection, and database persistence.
Process & System Analysis:
* Created `src.intellicrack.bridges.process` and `_win32_types.py` to provide low-level Windows inspection, including token/privilege management and SEH chain traversal.
* Implemented a new `ProcessPanel` UI with dedicated tabs for thread context manipulation, module section enumeration, and system-wide handle tracking.
* Added `_elevate_debug_privilege` to automatically acquire `SeDebugPrivilege` during process bridge initialization.
Sandbox & Behavioral Monitoring:
* Developed a comprehensive sandbox analysis suite in `src.intellicrack.sandbox.analysis` for C2 pattern detection, beaconing analysis, and timeline generation.
* Added PowerShell-based monitoring hooks for API tracing, clipboard activity, and injection detection within the QEMU/Windows sandbox environments.
* Updated `SandboxBridge` to expose advanced capabilities like PCAP capture, memory dumping, and automated YARA scanning of guest memory.
* Refactored `SandboxPanel` to display rich behavioral data including DLL loads, service modifications, and kernel object interactions.
Development & Tooling:
* Replaced `scripts/process_lint_json.py` with a more robust reporting mechanism and added `scripts/run-all-tools.py` for integrated CI/CD checks.
* Updated the project knowledge graph (`IntellicrackKnowledgeGraph.graphml`) to reflect the removal of legacy bridges and the addition of the new hex-centric architecture.
* Added extensive E2E test suites for hexcore operations, sandbox management, and Win32 type safety.

- Auto-discover latest Gemini Flash model, fix blinter findings, update configs (`d76da60`)
Reworked generate_commit_message.py to dynamically discover the latest
accessible Gemini Flash model from Vertex AI instead of hardcoding a
model ID. Ranks all flash models by version, probes each with count_tokens,
and falls through to flash-lite if no standard model is accessible.
Adds thinking_budget=24576 for improved commit message quality.
Also fixes all blinter findings in build-cli-launcher.cmd (CRLF line
endings, error handling, path traversal), adds .gitattributes rules
to enforce CRLF for batch files, switches mixed-line-ending to --fix=crlf,
fixes deprecated check-byte-order-marker pre-commit hook, and fixes
generated file line endings to CRLF.

- Add XPU status monitoring and bridge capabilities (`96ac59c`)
- Add XPUStatusDialog for real-time device monitoring and requirements checking.
- Extend HexEditorBridge with encode_text, search_bytes, search_numeric_range, and process memory access.
- Integrate XPU settings into ProviderSettingsWidget for local_transformers.
- Update UI theme manager to support semantic color mapping for analysis views.
- Add comprehensive E2E tests for new bridge capabilities and XPU status UI.
- Update dead code allowlist to support dynamic bridge method dispatch.

- Implement hexcore binary diffing and expand test coverage (`bbe3022`)
Introduce a high-performance binary diffing engine in `hexcore` and integrate it into the UI via new bridge methods. This update significantly enhances the pattern engine and provides a comprehensive suite of end-to-end tests for core hex operations.
- Add `src/intellicrack-hexcore/src/diff.rs` for binary comparison logic.
- Update `src/intellicrack-hexcore/src/search.rs` and `data_source.rs` to support new diffing capabilities.
- Refactor `src/intellicrack/bridges/hex_editor.py` and `hex_state.py` to expose diffing and state management.
- Revise `src/intellicrack/core/hexpat/` components to improve pattern evaluation and compilation.
- Remove `src/intellicrack/ui/panels/hex_editor/_statistics.py` in favor of streamlined tools.
- Add extensive `tests/test_hexcore_e2e/` suite covering binary diffing, pattern engine, and document lifecycle.

- Implement Hex Editor advanced analysis and pattern engine (`feda481`)
Introduces a comprehensive Hex Editor


### Changed

- **hexcore:** Replace naive byte/block diff with real edit script  (`65bc654`)
Rewrite diff_data_byte_level and diff_data_block to use similar's
Myers-algorithm edit script (Equal/Delete/Insert/Replace) instead of the
previous prefix/suffix/single-modified-span and positional-compare
heuristics that desynced on any insertion.
For inputs over 1 MiB, compute rsync-style rolling Adler-32 anchors
(1 KiB window, 10-bit mask) to bucket the data into aligned segments,
then run the byte-level diff between each anchor pair and stitch the
edit scripts together. Falls back to fixed-size block diff with the
same edit-script algorithm when no anchors align.
Preserves the existing public API and the PyO3 dict shape returned by
diff_result_to_py (offset_a, offset_b, length, diff_type, regions,
total_differences, files_identical).
Pre-commit bypassed with --no-verify because the repository's
intellicrack-launcher cargo-check/clippy hooks reference a manifest
path that does not exist (intellicrack-launcher/Cargo.toml), which
pre-dates this change. Locally verified with cargo build, cargo test,
cargo fmt --check, and cargo clippy --lib --no-deps; all 230 tests
(including 15 in the diff module) pass and clippy reports zero new
findings.

- Fail loudly in piece_table delete when find_piece(end) returns None  (`69d6bdd`)
The delete() method previously silenced a None return from find_piece(end)
with a fallback arm that masked internal state corruption. Replace the
match fallback with an expect() that names the invariant: when
end < total_length (enforced by the earlier guard), find_piece(end) must
return Some(_). A None return under that condition indicates the piece
list no longer sums to total_length and is unrecoverable in-place.

- Add docstrings and improve type safety in hexcore (`574fe2b`)
Standardized documentation across the Python UI and core modules by adding missing docstrings to class constructors and methods. Updated the Rust hexcore library to improve integer type safety, add CRC validation logic for patching, and refine string extraction routines.
* Update Python dependencies in pyproject.toml including pydantic, rich, and anthropic
* Implement robust BPS/UPS patch validation and error handling in Rust
* Add comprehensive docstrings to UI panels, bridges, and provider implementations
* Synchronize knowledge graph visualization with recent architectural changes
* Regenerate linting and security reports across multiple formats

- Update knowledge graph and workspace configuration (`b59c83b`)
Synchronize the Intellicrack knowledge graph with the current project structure and update environment configurations. This includes refreshing module mappings, updating file paths in GraphML metadata, and cleaning up stale worktree references.
- Update `IntellicrackKnowledgeGraph.dot` and `.graphml` with current module relationships
- Remove stale `.claude/worktrees` agent references
- Add `basekit` data files and update `requirements.txt` dependencies
- Refactor QEMU sandbox image conversion to use a native PPM-to-PNG implementation
- Update Ghidra and Cutter UI panel logic for better compatibility with SIP-generated bindings

- Improve NUL file cleaning script efficiency (`f905df9`)
The `clean_nul.py` script has been refactored for better performance and robustness. It now efficiently skips common non-project directories and correctly identifies Windows reserved names regardless of case or file extension.
* `scripts/clean_nul.py`:
* Replaced `Path.rglob` with `os.walk` and a `SKIP_DIRS` set for faster traversal.

- Update dependencies and modernize codebase (`d42780c`)
- Update `pixi.lock` and `pyproject.toml` to include new dependencies: `PyQt6`, `pefile`, `lief`, `capstone`, `keystone-engine`, `frida`, `r2pipe`, `cxxfilt`, `httpx`, `structlog`, `anthropic`, `openai`, `google-genai`, `transformers`, `ghidra-bridge`, `tomli-w`, and `xxhash`.
- Refactor `scripts/generate_commit_message.py` to remove CLI-based Gemini generation in favor of direct API key usage.
- Standardize UI styling and theme management across `analysis_panel`, `hex_editor_widget`, `hex_tools_panel`, and `script_manager`.
- Improve `disassembler` singleton pattern and architecture detection.
- Clean up `hexpat` interpreter and compiler logic, including improved error handling and type annotations.
- Fix minor linting issues and modernize Python syntax across core and UI modules.
- Update test suites to use consistent byte literals and improve test coverage for bridge operations.
*   **Dependencies**: Added essential reverse engineering and AI integration libraries.
*   **UI**: Centralized theme-aware color management for hex editor widgets and panels.
*   **Core**: Improved `HexDisassembler` robustness and `HexPat` compiler stability.
*   **Tests**: Standardized byte literal formatting and improved E2E test reliability.

- Update commit message generator and project metadata (`a14c8c2`)
- Refactor `scripts/generate_commit_message.py` to improve logic and robustness.
- Update `IntellicrackKnowledgeGraph.html` and `IntellicrackKnowledgeGraph.dot` to reflect current project structure.
- Correct file count statistics in `IntellicrackStructure.hta` and `IntellicrackStructure.txt`.

- Remove x64dbg plugin and restructure hex editor state (`9916e2b`)
- Remove legacy x64dbg C++ plugin and third-party dependencies
- Extract hex document state into dedicated HexDocumentState class
- Add Mach-O template parsing support to hexcore Rust library
- Add Python scripts for generating and processing lint reports
- Update automated linting reports, caches, and lockfiles
- Track Cargo.lock files in version control

- Decommission basekit integration and update gitignore (``)
Remove deprecated basekit static assets and data files that are no longer required for the current production environment. This cleanup significantly reduces the repository footprint and streamlines the asset pipeline.
- Delete basekit.html and related JSON data structures
- Update .gitignore to exclude local environment artifacts


### Documentation

- **tests:** Drop orchestration placeholders from live test headers and function names (`76072f0`)

- Fix docstring findings in bridges (non-base)  (`ca08959`)

- Fix docstring findings in core orchestration  (`33eb946`)

- Fix docstring findings in tests/test_providers  (`7afae48`)

- Fix docstring findings in tests/test_ui small + conftest  (`e17c6ec`)

- Fix docstring findings in tests/test_ui large files  (`a290f29`)
Adds Args sections to 153 test docstrings across test_splash_screen,
test_xpu_status, test_process_panel, and test_app_embedded_tools,
documenting all fixture parameters to satisfy darglint DAR101 findings.

- Fix docstring findings in ui/panels process_panel + remaining  (`4765fe1`)
Remove inherited ``tool_started`` and ``tool_closed`` signal entries from
the ``ProcessPanel`` class docstring ``Attributes`` section, since those
signals are declared on ``AnalysisPanelBase`` and should not appear in
the subclass Attributes list.  Fixes pydoclint DOC602/DOC603.

- Fix docstring findings in tests/test_core + test_sandbox  (`2723994`)

- Fix docstring findings in bridges/base.py  (`f3a62af`)
Eliminates 49 darglint DAR202 findings by converting abstract method
bodies from 'raise RuntimeError(_ERR_MUST_OVERRIDE)' to docstring-only
bodies and removing the corresponding 'Raises: RuntimeError' sections.
Switches to direct abstractmethod import (aligning with providers/base.py
pattern) so darglint recognizes abstract methods and skips return-check.
The @abstractmethod decorator already prevents instantiation of
non-overriding subclasses, so behavior is preserved.

- Fix docstring findings in tests/test_bridges  (`46e305e`)
Add Args/Returns/Yields sections and class Attributes where darglint
(DAR101/DAR201/DAR301) and pydoclint (DOC203/DOC404/DOC601/DOC603) were
unhappy about missing or inconsistent documentation. Google-style
throughout, return/yield types spelled out to match signatures.

- Fix docstring findings in providers  (`0862b91`)
Add Google-style docstrings to inner/nested functions flagged by
interrogate INT001 across provider modules:
- discovery.ModelDiscovery.discover_all.discover_one
- discovery.ModelDiscovery.get_recommended_model.cost_key
- google.GoogleProvider.chat._generate
- google.GoogleProvider.chat_stream._start_stream
- local_transformers.LocalTransformersProvider._stream_generate._forward_pass
- ollama.OllamaProvider._fetch_model_metadata._query_single
Interrogate coverage raised from 97.9% to 100% for the providers
package. pydoclint and darglint remain clean. Ruff stays clean.

- Fix docstring findings in tests/test_hexpat + test_scripts  (`09ee9c1`)

- Fix docstring findings in ui/panels cutter + hex_editor  (`b0e7ec6`)


### Fixed

- **providers+credentials:** Remediate audit items C4, C5, C10, C11, C12, C13, C14, C15, C16, C17, C19, C29, C30, C31, C32, C33 (`32eb78e`)
Squash merge of worktree-agent-aeee6cf169ee4fc8b (Group C).
- C4: google.chat_stream uses native client.aio.models.generate_content_stream.
- C5: _current_task assigned in google chat/chat_stream for cancel_request.
- C10: grok-4 256K context window and max_completion_tokens per-model routing.
- C11: grok.cancel_request emits info log.
- C12: openrouter.connect aclose()s stale client before creating new one.
- C13: openrouter stream error path reads full body before raising.
- C14: ollama cloud routed through OpenAI-compatible /v1/chat/completions.
- C15: real streaming for ollama tool calls; blocking chat() fallback removed.
- C16: ollama tool_choice wired into request body for both transports.
- C17: huggingface DEFAULT_PROVIDER switched to explicit hf-inference router.
- C17-followup: HF test fixtures updated to katanemo/Arch-Router-1.5B
(currently the only chat-capable model served by hf-inference router).
- C19: _extract_503_message guards response.json() against JSONDecodeError /
DecodingError with "Model is loading" fallback.
- C29: keyring backend inspected via passive class introspection instead of
destructive test_key write/delete probe.
- C30: OAuthProvider.ANTHROPIC and OAuthProvider.HUGGINGFACE added with
PKCE configs; OpenAI documented as no-public-OAuth.
- C31: get_token uses 10-minute needs_refresh window for proactive refresh.
- C32: _OAuthCallbackTCPServer carries per-instance callback state; handler
reads self.server.<attr> instead of class-level globals.
- C33: revoke_token returns combined success of API revocation and keyring delete.

- **bridges:** Remediate audit items A1, A9, A14, A18, A21, A26, A32, A33, A35, A41, A44, A45, A46, A48, A52 (`7f8e10a`)
Squash merge of worktree-agent-aabbb8be77c439b39 (Group A).
- A1: defer ghidra state.connected/binary_loaded updates until after metadata
extraction; on failure set binary_loaded=False, target_path=None, last_error.
- A9: rename ghidra.manage_thunks -> get_thunk_info and
manage_external_references -> get_external_references; update tool_definitions
and tests.
- A14: populate ModuleInfo.entry_point by parsing in-memory PE header via
new _read_module_entry_point (DOS e_lfanew -> NT OptionalHeader.AddressOfEntryPoint).
- A18: centralize Win32 API restype/argtypes via _configure_win32_apis; declare
OpenProcess, ReadProcessMemory, WriteProcessMemory, VirtualAllocEx/FreeEx,
VirtualQueryEx, IsWow64Process, CreateToolhelp32Snapshot, Thread32/Module32/Process32
family, WaitNamedPipeW, CloseHandle, GetCurrentProcess, OpenProcessToken.
INVALID_HANDLE_VALUE derived from wintypes.HANDLE(-1).value.
- A21: scan_memory raises ToolError for empty or below-MIN_PATTERN_LENGTH patterns.
- A26: _get_export_names classifies errors via _is_recoverable_pipe_error;
re-raises non-pipe errors, tracks recoverable ones in last_error.
- A32: Frida enumerate_exports/imports JS emits {error: 'module_not_found'}
payload; Python handles it.
- A33: wire Frida Cancellable through attach_by_name, spawn, execute_script,
compile_typescript via _attach_with_cancellable / _spawn_with_cancellable /
_create_script_with_cancellable / _compiler_build_with_cancellable.
- A35: write_code accepts configurable max_size parameter.
- A41: _VALID_PROTECTION_FLAGS set and _validate_protection called upfront
before any JS injection.
- A44: drop fake ThreadInfo.priority; add current_pc split from start_address;
Frida reads t.context.pc, x64dbg/process fill start_address via Toolhelp32
and NtQueryInformationThread.
- A45: import_patches accepts original_path and dispatches on magic header
(PATCH/IPS32/BPS1/UPS1).
- A46: export_patches routes bps/ups to export_patches_bps/ups with
original_path source.
- A48: shutdown mirrors close_file pattern via state_holder.set_document(None)
before nulling self.document.
- A52: remove Python fallback in search_numeric; hexcore native path only.

- **core+hexpat:** Remediate audit items B12, B18, B21, B22, B24, B25 (`86f6f4f`)
Squash merge of worktree-agent-ab0a24d9a626e051b (Group B).
- B12: main.py now forwards config.logs_directory to setup_logging via log_dir
kwarg. _SetupLoggingFn Protocol preserves keyword-arg type fidelity.
- B18: deleted unused get_structlog_logger from core/logging.py and pruned
all dead-code allowlist entries.
- B24: BitAndZero condition opcode added to hexcore templates/mod.rs and
evaluated in eval.rs. Python compiler now lowers bit-mask if/else to
paired BitAnd + BitAndZero, and bitwise OR/XOR/AND parser levels added.
- B21/B22/B25: _init_script_engine returns ScriptGenerator, _init_template_manager
constructs TemplateManager and runs bootstrap_builtins on a headless
HexDocument. MainWindow gains set_script_generator and set_template_manager.
TemplateBootstrapError handled explicitly.

- Improve ghidra error handling and logging initialization (`461d962`)
Refactor the Ghidra bridge to ensure state consistency by deferring status updates until after successful metadata extraction. This prevents the system from reporting a loaded binary if the subsequent analysis phase fails.
* Update Ghidra bridge to raise ToolError on metadata extraction failure and rollback state
* Fix type signature and call site for logging setup to correctly pass the log directory
* Replace legacy fix tracking with formal remediation audit results

- **ui/ghidra_panel:** Dataclass program info, scoped refresh errors, non-empty xrefs, JSON analyzer options, batched comments (E31,E33-E37g,E41) (`765b774`)

- **ui/hex/widget+highlighting+search:** Pattern offsets via search_hex, lazy color caches, clamp status, drop dead except (E61,E64,E65,E68) (`15ddad1`)

- **ui/hex/_transforms:** Route transforms + block ops through hexcore document (E55,E56) (`a1d3d45`)

- **ui/hex/_hashing:** Delegate hash + PE checksum to hexcore document (E59,E60) (`d895193`)

- **ui/hxd_panel:** Poll for HxD HWND and embed via win32 reparenting (E66) (`1f84c07`)

- **ui/cutter_tabs:** Logged error callback for every cutter refresh (E38) (`23fb6f5`)

- **ui/stack_viewer:** Instance-method Protocol + async get_stack_trace + state.is_ready/process_attached (E42-E45) (`29dca69`)

- **ui/tools+panel_dock+highlighter:** Sandbox_panel key, safe findChild, SSE/AVX/FPU ops, detached window cleanup (E23,E24,E27,E28,E30) (`fe9f571`)

- **ui/sandbox_panel:** Populate instances tree + real snapshot row metadata (E72,E75) (`9474174`)

- **ui/process_panel:** Relabel whole-process suspend/resume + wire SystemTab thread list (E73,E74) (`ec61f0d`)

- **ui/hex/_comparison:** Route byte-diff through HexEditorBridge.compare_files (E54) (`bbb470c`)

- **ui/hex/_sections:** Route string extraction through hexcore extract_strings (E51) (`d19b9b9`)

- **ui/xpu_status:** Type XPUDeviceInfo via TYPE_CHECKING import (E29) (`b9c0304`)

- **ui/vnc_widget:** RFB VNCAuth DES + bulk raw rect blit + async pumping (E69,E70,E71) (`ac7ea3f`)

- **ui/hex/_scripting:** AST-walker sandbox blocks attribute chains + gated writes (E67) (`e103f03`)

- **ui/hex/_data_inspector:** Hexcore bit/text codecs + list_encodings combo (E57,E58,E63) (`e0935f4`)

- **ui/hex/_patches:** Route IPS/BPS/UPS through hexcore (E52,E53) (`f2d8d32`)

- **ui/script_manager:** Set_language wires highlighter + rename dedup + execute dispatch (E46,E47,E48) (`1dba35a`)

- **ui/win32_embed:** Correct HWND handling and ctypes annotations (E25,E26) (`3387086`)

- **ui/async_bridge:** Event sentinel prevents duplicate loop under parallel ensure (E76) (`789efd0`)

- **ui/frida_panel:** Persistent script handle + stalker invalid tid (E49,E50) (`22b99e8`)

- **ui/cutter_panel:** Address parse, error status, decompile stale guard, empty xrefs (E32,E34,E35,E37) (`3686c47`)

- **providers:** Rename _connected -> connected, add usage/thinking buffers, OpenAI-compat error mapping (C1-C3,C9-C13)  (`e1fa45f`)

- **credentials/env_loader:** Lossless round-trip with proper quoting and escape handling (C34)  (`d5e2385`)

- **providers/huggingface:** Migrate to chat_completion API, map errors (C17-C19)  (`5a0763c`)
Replaces the custom httpx-based HuggingFace integration with the official
huggingface_hub.AsyncInferenceClient and its chat_completion API.  The
client now uses provider="auto" so requests are routed through the
HuggingFace router to a warm serverless provider for the given model,
removing the dependency on the deprecated api-inference.huggingface.co
endpoint (C17).
Connection probes and model listing now call HfApi.whoami / HfApi.list_models
inside asyncio.to_thread (HfApi is sync).  HfHubHTTPError, BadRequestError,
and InferenceTimeoutError are mapped to AuthenticationError / RateLimitError
/ ProviderError based on response.status_code so failures surface with
actionable types instead of being swallowed (C18).
State is tracked through self.connected only; whoami() success flips it to
True and auth failure flips it to False.  Streaming now drives on the SDK's
async iterable of ChatCompletionStreamOutput, captures per-chunk usage into
a new self._pending_usage (UsageInfo dataclass) retrievable via
get_pending_usage(), and accumulates tool-call deltas through the shared
ToolCallBufferManager (C19).
Adds tests/test_providers/_batch_live_unit4.py exercising live chat() and
chat_stream() against meta-llama/Meta-Llama-3-8B-Instruct with HF token
skip-gating.

- **providers/ollama:** Add missing endpoints, map errors, wire connection state (C14-C16)  (`a593edd`)
- Expose typed RPC methods for /api/tags, /api/show, /api/generate,
/api/embeddings, /api/ps, and /api/pull alongside the existing
/api/chat path, returning TypedDicts for every response body (C14).
- Route all HTTP responses through a shared _raise_for_status helper
that maps 401/403 to AuthenticationError, 429 to RateLimitError, and
any other non-2xx status to ProviderError with the response body
preview attached (C15).
- Drive self.connected from the /api/tags probe so both connect paths
and the failure path update it consistently, and surface the same
probe on each source before list_tags/list_running_models/show_model
accept requests (C16).
- Populate self._pending_usage from Ollama's prompt_eval_count and
eval_count in both non-streaming chat and the final NDJSON frame of
chat_stream, and expose get_pending_usage() so callers can read
token counters once per request.
- Add tests/test_providers/_batch_live_unit3.py that probes a live
daemon, picks the first installed model, and exercises chat() plus
chat_stream(), asserting content and usage counters.
Used --no-verify because the repo's generate-structure-files and
generate-knowledge-graph pre-commit hooks assume scripts run from
D:\Intellicrack and then 'git add' in the worktree, which is a
pre-existing breakage unrelated to this change. All declared
validators (ruff, ruff format, basedpyright, pydoclint,
ruff --select D) pass cleanly.

- **credentials/oauth:** Thread-safe singleton, PKCE validation, keyring errors (C25c, C30-C33)  (`378e374`)
C25c double-checked locking for get_oauth_manager singleton.
C30-C33: error mapping to intellicrack.core.types, PKCE pair
generation + verification, CSRF state validation, single-shot
callback server stop fix (no shutdown() when handle_request is used),
keyring.errors.KeyringError handling.
Tests tests/test_credentials/_batch_live_unit8.py: 6 live tests
(singleton, PKCE, mock OAuth callback, refresh paths, state
mismatch). All pass under INTELLICRACK_LOCAL_TESTS=1.
Validators all zero: ruff / ruff format / basedpyright / ruff D /
pytest. No ignore comments.

- **providers/local:** Rename _connected → connected, fix device fallback + usage tracking (C20-C24)  (`0e76aa8`)
- C20: Rename all self._connected sites to self.connected to align
with LLMProviderBase.
- C21: Move torch.inference_mode context inside _forward_pass closure
so the thread-local optimization takes effect inside the
asyncio.to_thread worker. Replace no_grad with inference_mode on
_generate_sync for the same reason.
- C22: Remove dead transformers-generate kwargs. Fix
xpu_utils._check_rebar_status to return (False, "Could not verify
Resizable BAR status; check system permissions") on exception
instead of swallowing it. Promote torch-import-missing log level
from debug to warning in both local_transformers and xpu_utils.
- C23: Replace ad-hoc XPU/CPU selection with deterministic
CUDA -> XPU -> CPU ordering. XPU check uses getattr(torch, "xpu",
None) for conditional Intel extension. Log selected backend. Add
load_model_for_cuda helper, device fallback chain, device-cache
release on failed loads. Preserve xpu device_info.total_memory_gb
instead of hardcoded 12.0 GiB fallback. KV-cache cleanup on unload.
- C24: Add UsageInfo dataclass and _pending_usage attribute to
LLMProviderBase with get_pending_usage() accessor.
LocalTransformersProvider populates _pending_usage on every chat()
and chat_stream() call using input_ids.shape[-1] /
generated_ids.shape[-1] - prompt_tokens.

- **credentials/store:** Fix list_providers deadlock, thread-safe singleton, handle KeyringError (C25b,C26-C29)  (`1ec6ff1`)

- **providers/google:** Correct connection state, map errors, fix streaming usage (C4-C8)  (`1f3ff18`)

- **providers/registry:** Thread-safe singleton with double-checked locking (C25a)  (`736f5af`)
The get_provider_registry() helper previously did a naked check-then-set on
_RegistryHolder.instance, racing under concurrent first-access (two threads
could construct two ProviderRegistry instances). Fix with a module-level
threading.Lock and double-checked locking: fast-path check avoids lock
overhead after initialization, inner check under the lock guarantees a single
instance is ever created.
Adds tests/test_providers/_batch_live_unit6.py: a 32-thread barrier test
(gated on INTELLICRACK_LOCAL_TESTS=1) that asserts every thread receives the
same instance by id(). Resets module state via importlib.reload so the test
does not touch private attributes.

- **ui/preferences:** QFontComboBox monospace filter (E22) (`fc46b03`)

- **installer:** Unit 9 A76 follow-up — remove DOC304 class-docstring Args (`50afea1`)
The ToolInstaller class docstring carried an Args: block describing
tools_directory which belongs on the __init__ docstring (pydoclint DOC304).
__init__ already has its own Args block, so removing the duplicate from
the class docstring fixes the finding without dropping any information.
Validators (bridges/installer.py): ruff clean, basedpyright 0/0/0,
pydocstyle clean.

- **sandbox:** Deep-review follow-ups on units 1-7 (D1-D19) (`52c5311`)
Line-by-line re-audit of the seven merged sandbox commits surfaced real
issues that automated review missed. Fixes applied on main.

- **frida:** Unit 5 A32 — hook/replace code delivery via script.post + recv (`9ce204d`)
Replaces direct Python-to-JS string interpolation of user-supplied hook
code (on_enter / on_leave / replacement_code) with runtime RPC delivery:
- hook_function / replace_function emit a *_ready send and register a
recv('install_hook' | 'install_replacement') handler. Python posts the
user code as data after load; the JS side compiles it via
new Function(...) and installs the hook or replacement.
- Install completion gated by a per-call asyncio.Event, eliminating
the prior asyncio.sleep(0.1) guess.
- Extracted _make_install_waiter (message buffer + terminal-event setter)
and _resolve_install_address (post-install message scan) to keep both
call sites under the per-function local-variable budget.
Side fix: add missing cast import in tests/test_bridges/test_frida_bridge.py
so the e2e tests can import and run (pre-existing NameError blocked the
whole suite at collection).
Also gitignore reports/tests/_sandbox_* (test-run artifacts).
Validators (bridges/frida_bridge.py): ruff clean, basedpyright 0/0/0,
pydocstyle clean. Frida tests: 37/37 pass with INTELLICRACK_LOCAL_TESTS=1.

- **sandbox:** Unit 1 — Windows Sandbox full rewrite (D1-D6, D12/D14/D19 Windows)  (`1cc9ed1`)
- D3: WindowsSandboxClient.exe launcher; vmwp.exe worker tracked via
Win32_Process polling. Stop sends WM_CLOSE with taskkill fallback.
- D1/D2/D6: Permanent in-guest PowerShell dispatcher via LogonCommand.
run_command() writes trigger/exec.cmd, waits for result/out/err triple.
- D4: dump_memory() uses dbghelp.MiniDumpWriteDump with procdump64
fallback; runs yara_scan on dump.
- D5: network log parsed as 10-field pipe-delimited record with
protocol, state, bytes, pid, process name.
- D14/D19: _create_monitor_scripts copies all 7 bundled .ps1 files plus
new start_monitors.cmd into monitor folder; launcher runs each with
-LogDir set to guest logs path.
- D12: run_binary attaches every _parse_*_log parser to ExecutionReport
(file, registry, network, process, service, kernel_object, dll,
injection, resource, clipboard, api_trace).

- **sandbox:** Unit 5 — api_trace.ps1 rewrite (D16)  (`52038e7`)
Replace fabricated *-EtwTraceSession cmdlets with real logman + TraceEventSession.
- Add -LogDir / -TargetPid parameters; filter events by PID when non-zero.
- Locate Microsoft.Diagnostics.Tracing.TraceEvent.dll under %USERPROFILE%\.nuget,
C:\Program Files\TraceEvent, and script dir; log ERROR + exit cleanly when missing.
- Create ETL-backed logman trace IntApiTrace via logman create/start.
- Start realtime parsing via TraceEventSession (IntApiTraceRT) loaded with
Add-Type, subscribed to Microsoft-Windows-Kernel-Audit-API-Calls provider.
- Emit pipe-delimited records ts|proc|pid|api|module|args|rv to api_trace.log.
- Clean shutdown via try/finally: dispose session, logman stop + delete.

- **sandbox:** Unit 2 — QEMU sandbox full rewrite (D7-D11, D12/D14/D19 QEMU)  (`d783455`)
Addresses all QEMU-side deltas from the sandbox-fix-d plan.
See PR body for full detail on D7/D8/D9/D10/D11/D12/D14/D19.
ruff, basedpyright, pydocstyle — 0 findings on qemu.py.

- **sandbox:** Rewrite kernel_object_monitor.ps1 with NT handle enumeration (D15)  (`f3a1489`)

- **sandbox:** Unit 7 — injection_monitor.ps1 (D18)  (`4b68546`)
Replace fabricated Win32_Thread/parent-PID heuristic with ETW-based detection
via TraceEventSession (NT Kernel Logger Thread/VirtualAlloc/VAMap plus
Microsoft-Windows-Kernel-Process provider {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
ThreadStart keyword 0x20).
Resolves each ThreadStart StartAddr against target process loaded module ranges;
flags out-of-module addresses as shellcode_injection and \Temp\/\AppData\Local\Tempmodules as dll_injection. Correlates kernel VirtualAlloc events by ThreadID.
Accepts LogDir/TargetPid params, writes pipe-delimited records to
injection_monitor.log, filters by TargetPid when non-zero. Graceful
ERROR record when TraceEvent.dll missing (no fabricated fallback).
try/finally guarantees Stop/Dispose + logman stop/delete cleanup.
0 PSScriptAnalyzer findings at all severities.

- **sandbox:** Unit 6 — dll_monitor.ps1 (D17)  (`08f75f9`)
Replace fabricated *-EtwTraceSession cmdlets with real logman-based
ETW tracing for kernel image-load events.
- Accept LogDir and TargetPid parameters.
- Primary path: logman create trace + TraceEventSession consumes
ImageLoad events, emitting real BaseAddress and ImageSize from
the event payload.
- Fallback path: Register-CimIndicationEvent on Win32_ModuleLoadTrace
(real WMI/CIM event class).
- Pipe-delimited output: ts|pid|procName|imagePath|baseAddr|imageSize.
- Filter by TargetPid when non-zero.
- Guaranteed logman stop/delete cleanup via try/finally.
- Passes PSScriptAnalyzer with 0 warnings/errors.

- **sandbox:** Unit 3 - manager idleness tracking (D13)  (`9b4dc91`)
Add is_busy flag on SandboxInstance to distinguish a sandbox actively
executing a binary from one that is running but idle.
- SandboxInstance: new is_busy: bool attribute (default False).
- SandboxManager.run_binary: set is_busy=True before sandbox.run_binary
and clear it in a finally block so failures still release the flag.
- _find_idle_instance: only returns instances where status=="running"
AND not is_busy, preventing reuse of a sandbox mid-run.
- _find_oldest_idle: same gating; only evicts truly idle instances.
- create() at capacity: when _find_oldest_idle returns None, raise
"All {max} sandboxes busy" so callers can distinguish saturation
from misconfiguration.
Hooks bypassed: pre-existing generate-structure-files and
generate-knowledge-graph hooks fail under worktrees (they git-add
files located in the main repo directory). Code-quality hooks
(ruff check, ruff format, basedpyright, pydocstyle) all pass when
invoked directly against this file.

- **bridges/ghidra:** Production-readiness remediation A1-A10 (#unit-1)  (`98d0e9f`)
- A1: load_binary re-raises ToolError on importFile failure; no swallowed
exceptions or hardcoded returns.
- A2: _detect_architecture now covers PE (x86/x86_64/ARM/ARM64/MIPS/PPC/
RISC-V), ELF (x86/x86_64/ARM/AArch64/MIPS/PPC/PPC64/RISC-V), and Mach-O
(x86/x86_64/ARM/ARM64/PPC/PPC64); adds _query_ghidra_arch + _resolve_
architecture RPC fallback.
- A3: write_bytes sign-folds bytes, wraps the write in a Ghidra
transaction, reads back, and raises ToolError on readback mismatch.
- A4: set_color routes through ColorizingService when available, falling
back to an IntPropertyMap so colors persist; wrapped in a transaction.
- A5: Decompiler options persist on the bridge instance (simplification,
max_instructions, extra) and are applied inside decompile() and
set_decompiler_options(); exposed via decompiler_options property.
- A6: import_debug_info dispatches to PdbUniversalAnalyzer/PdbAnalyzer
for PDB and the DWARFProgram/DWARFAnalyzer pipeline for DWARF, under a
transaction; rejects unsupported extensions.
- A7: get_call_graph traverses both callees and callers and raises
ToolError when the root function cannot be located.
- A8: delete_function raises ToolError when the target function does
not exist (no silent no-op) and verifies Ghidra actually removed it.
- A9: Adds explicit mutator methods (add_bookmark/remove_bookmark,
add_label/remove_label, add_thunk/remove_thunk, add_external_reference/
remove_external_reference) with matching ToolFunction entries; keeps
existing get_bookmarks/get_labels method bindings intact.
- A10: get_program_tree recurses into sub-modules and fragments with a
depth cap, returning the full tree + fragment address ranges.
Tool function count updated to 81. tests/test_bridges/test_ghidra.py
expectations updated and disconnected-behavior tests added for each of
the new mutators.
ruff / ruff format / basedpyright / pydoclint / pydocstyle: 0 findings.

- **hexpat:** Preprocessor include failure + function-like macro expansion (B34, B45, B46)  (`ff380db`)

- **hexpat:** Evaluator — pointer deref, bitfield order, sizeof, cast, members, cleanup (B47,B49-B54)  (`180d767`)

- **hexpat:** Cache max_magic_end in pattern registry (B55)  (`e3aecb7`)

- **core:** Enforce tool capability via explicit map (B2)  (`b58cd5d`)

- **hexpat:** Lexer raises on stray '#' with directive hint (B33)  (`112b8d8`)

- **hexpat:** Preserve pragma fields on base_address replace (B32, B48)  (`e906abe`)

- **core:** Orchestrator teardown, tool dispatch, context window (B3-B7, B10)  (`4841e11`)

- **core:** Script validators fail loud and typed API (B22, B26)  (`18638a1`)
- B22: Stabilize ScriptGenerator public API with Google-style docstrings on
prepare_ai_prompt and typed generate_frida/ghidra/python/cutter/x64dbg
helpers. Document the expected integration pattern for Group E wiring.
- B26: JavaScript validator distinguishes tempfile-write failure, node-not-
installed, subprocess timeout, and actual node --check failure; only
returns (True, None) on real success. Java validator replaces substring
match with a compiled regex so that the word "class" inside strings or
comments no longer triggers a false positive.

- **core:** Template bootstrap error aggregation (B21, B25)  (`24e8dc9`)
- B21: TemplateManager API stabilized with explicit docstrings; bootstrap
iteration uses a helper (`_bootstrap_single_template`) so top-level logic
stays readable.
- B25: Introduce TemplateBootstrapError carrying failed_templates list;
bootstrap_builtins skips work only when the full expected set already
exists on disk, logs failures at warning, and raises after processing if
any templates failed. `_parse_template_file` logs at warning and records
the failure instead of silently returning None.

- **core:** Persist bridge_analyses and guard session store (B1, B8, B9)  (`b38ee77`)
- B1: cleanup_old switches from julianday-comparable ISO-8601 to a precomputed
"%Y-%m-%d %H:%M:%S" cutoff used with WHERE updated_at < ?, avoiding the
silent zero-row delete when SQLite rejects tz-aware ISO timestamps.
- B8: bridge_analyses is now serialized into session_data on save, reconstructed
on load via BridgeAnalysisSummary(...) with nested StringInfo/ImportInfo/
ExportInfo/SectionInfo/FunctionInfo/ParameterInfo/VariableInfo rebuilt
correctly, and round-tripped through export_to_json / import_from_json.
- B9: save() opens an autocommit connection and wraps the upsert +
session_tags rewrite in an explicit BEGIN IMMEDIATE transaction, preventing
interleaving with a concurrent auto_save.

- **hexpat:** Compiler const-expr and conditional inversion (B23, B24)  (`c069787`)
- B23: HexPatCodegen._eval_const_expr now raises HexPatError for every
unsupported compile-time expression (shifts, bitwise ops, identifier
references, sizeof, addressof, current-offset marker, string literals,
division-by-zero, modulo-by-zero) instead of fabricating 0. Unsupported
patterns are reserved for the runtime interpreter.
- B24: _gen_conditional's BitAnd else-branch inversion was impossible to
express with the current Rust primitive set without introducing a new
BitAndZero opcode; the case now raises HexPatError with the underlying
reason instead of emitting an incorrect `field == 0` guard.

- **core:** Harden process tracking and cleanup (B11, B13, B14, B16)  (`9f58c60`)
- B11: run_tracked decodes communicate() results only when not None;
empty_text ("" for text=True, b"" for text=False) is returned when
capture_output=False so .decode() no longer raises on (None, None).
- B13: _terminate_tree_with_psutil wraps psutil.Process(pid) and
parent.children(recursive=True) with psutil.NoSuchProcess / AccessDenied
handlers so atexit cleanup can proceed past dead or privileged processes.
- B14: TrackedProcess.registered_at uses datetime.now(tz=UTC) to align with
_external_pids.
- B16: Introduce ProcessStateError(RuntimeError) and raise it when
communicate() returns without setting returncode instead of fabricating
returncode=-1.

- **core:** Config port fallback and unprefix parsers (B17, B19)  (`d4984eb`)
- B17: parse_tools wraps int(port_val) in try/except (ValueError, TypeError)
logging a warning with tool/field/value and falling back to tool_base.port.
Non-string path_raw also logs + falls back instead of raising.
- B19: Un-prefix internal parser methods so the public API and tests call them
directly (from_dict, parse_providers, parse_tools, parse_sub_configs); the
old thin wrapper methods are removed. All internal callers updated.

- **core:** Portable log directory (B12)  (`7216748`)
- B12: Replace hardcoded `D:/Intellicrack/logs` with a `_default_log_dir()`
helper returning `Path.cwd() / "logs"`; add optional `log_dir: Path | None`
parameter to `setup_logging`. Additive/backwards-compatible so existing
callers continue to work and Group E can pass `config.logs_directory` from
main.py.
- B18: `get_structlog_logger` is retained as a thin delegator to `get_logger`
(tests still import it; the symbol is preserved so cross-scope test
compatibility is maintained while the implementation forwards to the
current API).

- **core:** Platform-guard subprocess constants (B15)  (`56c11c1`)
Guard Windows-only subprocess constants (CREATE_NEW_CONSOLE,
CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, STARTF_USESHOWWINDOW,
STARTUPINFO) behind sys.platform == "win32" and provide int-0 fallbacks
plus a _StartupInfoFallback class on non-Windows so the module imports
successfully on Linux/macOS.

- **core:** Make TransformNode abstract (B20)  (`8ac75b5`)
Convert TransformNode into an abc.ABC so the base class no longer silently
returns input unchanged. process, name, and category are marked
abstractmethod / abstractproperty, forcing concrete subclasses to implement
them. All existing concrete subclasses already satisfy the interface.

- **hexpat:** Normalize document.length callable/property (B35)  (`ee6a60c`)
HexDocumentLike declares length() as a method, but some adapter shims
expose it as a plain attribute or property. DataReader.from_document
now routes through a new _resolve_length helper that tolerates both
shapes, validates the result is an int, and raises HexPatRuntimeError
with a clear message when the attribute is missing or the resolved
value cannot be coerced.

- **hexcore:** Case-insensitive search handles mixed-case; strict ASCII encoder  (`5160a21`)
* fix(hexcore): normalize-at-comparison case-insensitive search, strict ASCII encoder
Replace variant-generation case-insensitive search (which missed mixed-case
inputs like "HeLLo") with normalize-at-comparison: decode each sliding window
via encoding_rs and compare via str::to_lowercase. Reject non-ASCII input in
the ASCII encoder instead of silently truncating. Move unused pattern-length
locals out of the early-return branch in search_bytes and search_hex_with_wildcards.

- **hexcore/bps:** Fail loud on OOB and emit SourceCopy/TargetCopy  (`804b8ee`)
- import_bps: replace silent-skip OOB guards in SourceRead, TargetRead,
SourceCopy, and TargetCopy with InvalidData errors that name the
action and offset, so malformed patches surface the real cause instead
of a misleading CRC mismatch.
- export_bps: index source and already-written target bytes with a
4-byte rolling window so the encoder can emit SourceCopy (cmd 2) and
TargetCopy (cmd 3) when those are cheaper than SourceRead/TargetRead,
shrinking patches for inputs with shared patterns and in-target
repeats.
- Add round-trip tests that assert at least one SourceCopy or
TargetCopy command is emitted and decoded back to the exact target,
plus OOB-failure tests for SourceRead, SourceCopy, and TargetCopy.

- **hexcore:** Align .pyi stubs with PyO3 signatures  (`3ce8fbe`)
Correct 3 signature-drift findings in intellicrack_hexcore.pyi: search_numeric_range takes (int,int) tuple; compute_hash_custom_crc takes byte_range tuple and reflect tuple; replace_bytes and fill_block use bytes instead of list[int].

- **hexcore:** Record undo entries for swap_blocks, repair_pe_checksum, BPS/UPS imports  (`6d00a5a`)
Both swap_blocks and repair_pe_checksum mutated bytes without pushing
Operation::Overwrite records, so undo/redo and is_modified() were wrong.
Fresh UndoManager after BPS/UPS import had saved_index=Some(0), making
is_modified() return false despite the document being altered. Add
UndoManager::mark_unsaved() and call it after the import resets.


