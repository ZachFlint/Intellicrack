# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [Unreleased]

### Added

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


