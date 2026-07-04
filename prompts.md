# Intellicrack Tool Viability Audit Prompts

Use each prompt independently in a separate conversation. Each prompt is self-contained and instructs Claude to perform a complete end-to-end pipeline audit for one embedded tool.

---

## Prompt 1: Ghidra

```
You are auditing the Ghidra integration in the Intellicrack project (D:\Intellicrack) for end-to-end viability. Your goal is to trace the ENTIRE pipeline from bridge initialization through GUI panel interaction, identify EVERY issue that would prevent this tool from working correctly when embedded in Intellicrack, and return a prioritized fix plan.

SCOPE - Read and analyze these files in full:

1. src/intellicrack/bridges/base.py — specifically the StaticAnalysisBridge base class and its parent ToolBridgeBase
2. src/intellicrack/bridges/ghidra.py — the GhidraBridge implementation
3. src/intellicrack/ui/panels/ghidra_panel.py — the GUI panel
4. src/intellicrack/ui/tools.py — the GhidraWidgetProtocol and add_ghidra_tab() wiring in ToolOutputPanel
5. src/intellicrack/core/tools.py — ToolRegistry registration and get_ghidra_bridge()
6. src/intellicrack/ui/tool_config.py — tool configuration/discovery dialog
7. src/intellicrack/core/orchestrator.py — any orchestrator methods that invoke Ghidra
8. src/intellicrack/ui/app.py — how the Ghidra tab gets created during app startup
9. src/intellicrack/bridges/__init__.py and src/intellicrack/ui/panels/__init__.py — export validation

WHAT TO CHECK at each layer:

BRIDGE LAYER (ghidra.py):
- Does GhidraBridge correctly inherit from StaticAnalysisBridge?
- Are ALL abstract methods from the base class implemented?
- Is ghidra-bridge (the pip package) imported and used correctly?
- Does initialize() properly discover the Ghidra installation path?
- Does connect() establish a working RPC connection on the correct port?
- Do all analysis methods (analyze_binary, get_functions, get_decompilation, get_xrefs, get_strings, get_imports, get_exports, etc.) actually call ghidra_bridge APIs correctly?
- Does disconnect/shutdown properly tear down the RPC connection?
- Are all tool_definitions entries correct and do they map to real methods?
- Does auto-download logic work (GitHub release fetching)?
- Error handling: what happens when Ghidra is not installed, not running, connection refused, RPC timeout?

GUI PANEL (ghidra_panel.py):
- Does GhidraPanel implement all methods required by GhidraWidgetProtocol (tool_started, tool_closed signals, start_tool, stop_tool, set_bridge, load_binary)?
- Does the panel properly call bridge methods and display results?
- Are Qt signals/slots correctly connected?
- Does the panel handle bridge errors gracefully (show error messages, not crash)?
- Can the panel start/stop the Ghidra process?
- Does the UI update correctly when analysis completes?

WIRING (tools.py, core/tools.py, app.py):
- Does ToolRegistry.initialize() create GhidraBridge correctly?
- Does add_ghidra_tab() in ToolOutputPanel correctly instantiate GhidraPanel, get the bridge from registry, and wire them together?
- Does the orchestrator route Ghidra commands correctly?
- Is Ghidra available in the tool config dialog for path setup?
- Are all imports resolvable (no circular imports, no missing modules)?

TYPE SAFETY:
- Are there any basedpyright type errors in the Ghidra pipeline?
- Are all type annotations correct and complete?
- Are Protocol implementations structurally compatible?

OUTPUT FORMAT:
For each issue found, report:
- FILE: exact file path and line number(s)
- ISSUE: clear description of the problem
- SEVERITY: Critical (blocks functionality) / High (causes errors in common flows) / Medium (edge case failures) / Low (code quality)
- FIX: specific description of what needs to change

At the end, provide a prioritized fix plan grouping issues by file, ordered from Critical to Low.
```

---

## Prompt 2: x64dbg

```
You are auditing the x64dbg debugger integration in the Intellicrack project (D:\Intellicrack) for end-to-end viability. Your goal is to trace the ENTIRE pipeline from the C++ plugin through the bridge through to the GUI panel, identify EVERY issue that would prevent this tool from working correctly when embedded in Intellicrack, and return a prioritized fix plan.

SCOPE - Read and analyze these files in full:

1. src/intellicrack/bridges/base.py — specifically DebuggerBridge, DynamicAnalysisBridge, and ToolBridgeBase
2. src/intellicrack/bridges/x64dbg.py — the X64DbgBridge implementation
3. src/intellicrack/ui/panels/x64dbg_panel.py — the GUI panel
4. src/intellicrack/ui/tools.py — the X64DbgWidgetProtocol and add_x64dbg_tab() wiring
5. src/intellicrack/core/tools.py — ToolRegistry registration and get_x64dbg_bridge()
6. src/intellicrack/ui/panels/stack_viewer.py — stack viewer that wires to x64dbg bridge
7. src/x64dbg-plugin/ — the ENTIRE C++ plugin source (intellicrack_bridge.cpp/.h, pipe_server.cpp/.h, command_handler.cpp/.h, and any CMakeLists.txt or build files)
8. src/intellicrack/ui/tool_config.py — tool configuration/discovery
9. src/intellicrack/core/orchestrator.py — orchestrator methods invoking x64dbg
10. src/intellicrack/ui/app.py — how the x64dbg tab gets created
11. src/intellicrack/bridges/__init__.py and src/intellicrack/ui/panels/__init__.py — export validation

WHAT TO CHECK at each layer:

C++ PLUGIN (src/x64dbg-plugin/):
- Does the plugin compile correctly for x64dbg's plugin SDK?
- Does the named pipe server start and accept connections?
- Does the command handler parse and respond to all commands the Python bridge sends?
- Is the protocol (message format, serialization) consistent between C++ and Python?
- Are there buffer overflow risks, memory leaks, or crash paths in the plugin?
- Does the plugin handle concurrent connections?

BRIDGE LAYER (x64dbg.py):
- Does X64DbgBridge correctly inherit from DebuggerBridge?
- Are ALL abstract methods from DebuggerBridge and its parents implemented?
- Does initialize() discover x64dbg installation correctly?
- Does connect() establish a named pipe connection to the plugin?
- Do ALL debugging operations work: attach/detach, breakpoints (set/remove/list), step (into/over/out), continue, memory read/write, register get/set, thread enumeration, module enumeration, stack frames, disassembly?
- Does the named pipe protocol match what the C++ plugin expects (same message format, same command names, same serialization)?
- Are Capstone/Keystone integrations correct for disassembly/assembly?
- Does auto-download work?
- Error handling: pipe disconnection, x64dbg crash, timeout, invalid responses?

GUI PANEL (x64dbg_panel.py):
- Does X64DbgPanel implement all methods required by X64DbgWidgetProtocol?
- Does the panel correctly display: registers, disassembly, memory dump, breakpoints, threads, modules, stack?
- Can the user interact with debugging controls (step, continue, break, set breakpoint)?
- Does the panel update when the debugger state changes (breakpoint hit, step complete)?
- Are Qt signals/slots correctly connected?
- Does the panel handle bridge errors gracefully?

STACK VIEWER INTEGRATION:
- Does the stack viewer correctly receive stack frame data from x64dbg bridge?
- Is _wire_stack_viewer_bridges() in ToolOutputPanel called at the right time?

WIRING:
- Does ToolRegistry create X64DbgBridge correctly?
- Does add_x64dbg_tab() wire everything together?
- Does the 32-bit vs 64-bit mode selection work?
- Are all imports resolvable?

TYPE SAFETY:
- basedpyright compliance across the entire pipeline
- Protocol structural compatibility

OUTPUT FORMAT:
For each issue found, report:
- FILE: exact file path and line number(s)
- ISSUE: clear description of the problem
- SEVERITY: Critical / High / Medium / Low
- FIX: specific description of what needs to change

At the end, provide a prioritized fix plan grouping issues by file, ordered from Critical to Low.
```

---

## Prompt 3: Cutter/Rizin

```
You are auditing the Cutter/Rizin integration in the Intellicrack project (D:\Intellicrack) for end-to-end viability. Your goal is to trace the ENTIRE pipeline from bridge initialization through GUI panel interaction, identify EVERY issue that would prevent this tool from working correctly when embedded in Intellicrack, and return a prioritized fix plan.

SCOPE - Read and analyze these files in full:

1. src/intellicrack/bridges/base.py — specifically StaticAnalysisBridge and ToolBridgeBase
2. src/intellicrack/bridges/cutter.py — the CutterBridge implementation
3. src/intellicrack/ui/panels/cutter_panel.py — the GUI panel
4. src/intellicrack/ui/tools.py — the CutterWidgetProtocol and add_cutter_tab() wiring
5. src/intellicrack/core/tools.py — ToolRegistry registration and get_cutter_bridge()
6. src/intellicrack/ui/tool_config.py — tool configuration/discovery
7. src/intellicrack/core/orchestrator.py — orchestrator methods invoking Cutter
8. src/intellicrack/ui/app.py — how the Cutter tab gets created
9. src/intellicrack/bridges/__init__.py and src/intellicrack/ui/panels/__init__.py — export validation

WHAT TO CHECK at each layer:

BRIDGE LAYER (cutter.py):
- Does CutterBridge correctly inherit from StaticAnalysisBridge?
- Are ALL abstract methods from the base class implemented?
- Is r2pipe imported and used correctly to communicate with Cutter/Rizin?
- Does initialize() properly discover the Cutter installation path?
- Does connect() establish a working r2pipe session (spawning Rizin or connecting to existing instance)?
- Do all analysis methods work via r2pipe commands: analyze_binary (aaa), get_functions (aflj), get_decompilation (pdgj/pddj), get_xrefs (axtj), get_strings (izzj), get_imports (iij), get_exports (iej), binary patching (w/wx)?
- Are r2pipe JSON responses parsed correctly (j suffix commands)?
- Does disconnect/shutdown properly close the r2pipe session?
- Are all tool_definitions entries correct and mapping to real methods?
- Does auto-download work?
- Error handling: Cutter not installed, Rizin spawn failure, r2pipe command errors, malformed JSON responses?

GUI PANEL (cutter_panel.py):
- Does CutterPanel implement all methods required by CutterWidgetProtocol (tool_started, tool_closed signals, start_tool, stop_tool, set_bridge, analyze_binary)?
- Does the panel properly call bridge methods and display results?
- Can the panel show disassembly, decompilation, functions, strings, imports/exports?
- Are Qt signals/slots correctly connected?
- Does the panel handle bridge errors gracefully?
- Can the panel start/stop the Cutter/Rizin process?

WIRING:
- Does ToolRegistry.initialize() create CutterBridge correctly?
- Does add_cutter_tab() in ToolOutputPanel correctly instantiate CutterPanel, get the bridge, and wire them?
- Does the orchestrator route Cutter commands correctly?
- Is Cutter available in the tool config dialog?
- Are all imports resolvable?

TYPE SAFETY:
- basedpyright compliance across the pipeline
- Protocol structural compatibility
- r2pipe return type handling (the library is poorly typed)

OUTPUT FORMAT:
For each issue found, report:
- FILE: exact file path and line number(s)
- ISSUE: clear description of the problem
- SEVERITY: Critical / High / Medium / Low
- FIX: specific description of what needs to change

At the end, provide a prioritized fix plan grouping issues by file, ordered from Critical to Low.
```

---

## Prompt 4: Frida

```
You are auditing the Frida runtime instrumentation integration in the Intellicrack project (D:\Intellicrack) for end-to-end viability. Your goal is to trace the ENTIRE pipeline from bridge initialization through GUI panel interaction, identify EVERY issue that would prevent this tool from working correctly when embedded in Intellicrack, and return a prioritized fix plan.

SCOPE - Read and analyze these files in full:

1. src/intellicrack/bridges/base.py — specifically InstrumentationBridge, DynamicAnalysisBridge, and ToolBridgeBase
2. src/intellicrack/bridges/frida_bridge.py — the FridaBridge implementation
3. src/intellicrack/ui/panels/frida_panel.py — the GUI panel
4. src/intellicrack/ui/tools.py — the FridaPanelProtocol and add_frida_tab() wiring
5. src/intellicrack/core/tools.py — ToolRegistry registration and get_frida_bridge()
6. src/intellicrack/ui/panels/stack_viewer.py — stack viewer Frida integration
7. src/intellicrack/ui/tool_config.py — tool configuration
8. src/intellicrack/core/orchestrator.py — orchestrator methods invoking Frida
9. src/intellicrack/ui/app.py — how the Frida tab gets created
10. src/intellicrack/bridges/__init__.py and src/intellicrack/ui/panels/__init__.py — export validation
11. Any Frida script files or templates in the project (search for .js files in src/intellicrack/)

WHAT TO CHECK at each layer:

BRIDGE LAYER (frida_bridge.py):
- Does FridaBridge correctly inherit from InstrumentationBridge?
- Are ALL abstract methods from InstrumentationBridge and its parents implemented?
- Is the frida Python package imported and used correctly?
- Does initialize() check for frida availability correctly?
- Do process operations work: spawn, attach (by PID and name), detach, resume?
- Do instrumentation operations work: inject_script, hook_function, unhook_function, replace_function, read_memory, write_memory, allocate_memory, protect_memory?
- Does the Stalker tracing integration work (trace_function, trace_thread)?
- Does enumerate_modules/enumerate_exports/enumerate_imports work?
- Does the API resolver work correctly?
- Are Frida message callbacks (on_message) handled correctly?
- Does child gating work?
- Does crash reporting work?
- Error handling: frida not installed, process not found, script compilation errors, device not found, permission denied, process crash during instrumentation?

GUI PANEL (frida_panel.py):
- Does FridaPanel implement all methods required by FridaPanelProtocol (tool_started, tool_closed signals, start_tool, stop_tool, set_bridge, log_message, add_hook_entry)?
- Can the user: attach to a process, write/load Frida scripts, execute scripts, view console output, manage hooks (add/remove/enable/disable), view modules/exports?
- Does the script editor work (syntax highlighting for JavaScript)?
- Does the console display Frida messages correctly (log, send, error)?
- Are Qt signals/slots correctly connected?
- Does the panel handle bridge errors and process crashes gracefully?
- Does the hook table update in real-time?

STACK VIEWER INTEGRATION:
- Does the stack viewer receive stack data from Frida correctly?
- Is _wire_stack_viewer_bridges() connecting the Frida bridge at the right time?

WIRING:
- Does ToolRegistry.initialize() create FridaBridge correctly?
- Does add_frida_tab() wire everything together?
- Does the orchestrator route Frida commands correctly?
- Are all imports resolvable?
- Does Frida auto-install via pip work?

TYPE SAFETY:
- basedpyright compliance (frida package has limited type stubs — check how types are handled)
- Protocol structural compatibility

OUTPUT FORMAT:
For each issue found, report:
- FILE: exact file path and line number(s)
- ISSUE: clear description of the problem
- SEVERITY: Critical / High / Medium / Low
- FIX: specific description of what needs to change

At the end, provide a prioritized fix plan grouping issues by file, ordered from Critical to Low.
```

---

## Prompt 5: Hex Editor

```
You are auditing the built-in Hex Editor in the Intellicrack project (D:\Intellicrack) for end-to-end viability. This is the most complex embedded tool — it spans a Rust native extension (PyO3), a Python bridge, a shared state holder, and a multi-file GUI panel. Your goal is to trace the ENTIRE pipeline, identify EVERY issue, and return a prioritized fix plan.

SCOPE - Read and analyze these files in full:

1. src/intellicrack/bridges/base.py — ToolBridgeBase (HexEditorBridge's parent)
2. src/intellicrack/bridges/hex_editor.py — the HexEditorBridge
3. src/intellicrack/bridges/hex_state.py — the shared HexDocumentState
4. src/intellicrack/ui/panels/hex_editor/ — the ENTIRE directory:
   - __init__.py
   - _base.py
   - _pattern_editor.py
   - panel.py (or whatever the main panel file is)
   - Any other files in this directory
5. src/intellicrack/ui/panels/hex_editor_panel.py — the panel entry point (if separate from the directory)
6. src/intellicrack/ui/tools.py — HexEditorPanelProtocol, add_hex_editor_tab(), _wire_hex_editor_state(), _on_hex_context_push()
7. src/intellicrack/core/tools.py — ToolRegistry registration and get_hex_editor_bridge()
8. src/intellicrack-hexcore/ — the Rust crate:
   - Cargo.toml (dependencies)
   - src/lib.rs (PyO3 module entry)
   - ALL .rs source files — check what Python-callable functions are exposed
9. src/intellicrack/ui/app.py — how the hex editor tab gets created
10. src/intellicrack/bridges/__init__.py and src/intellicrack/ui/panels/__init__.py — export validation
11. vendor/PatternLanguage/ and vendor/ImHex-Patterns/ — vendored pattern data (just check they exist and are referenced correctly)

WHAT TO CHECK at each layer:

RUST CRATE (intellicrack-hexcore):
- Does the crate compile successfully? Check Cargo.toml for dependency issues.
- What #[pyfunction] and #[pyclass] items are exposed to Python?
- Does the piece table implementation work for insert/delete/modify operations?
- Does memory-mapped file I/O work on Windows?
- Do hash functions (MD5, SHA1, SHA256, SHA3, BLAKE2, xxHash) work correctly?
- Does binary diff work?
- Does the template/pattern system work?
- Does YARA integration compile and function?
- Are there any unsafe blocks that could cause UB?

BRIDGE LAYER (hex_editor.py):
- Does HexEditorBridge correctly wrap the Rust hexcore functions?
- Does initialize() load the native extension correctly?
- Do all operations work: open_file, read_bytes, write_bytes, search, hash, diff, apply_template, scan_yara?
- Does the bridge handle the case where hexcore is not compiled/available?
- Are tool_definitions correct?

STATE MANAGEMENT (hex_state.py):
- Does HexDocumentState correctly track document state (file path, cursor, selection, modifications)?
- Is it thread-safe for concurrent access from bridge and panel?
- Does _wire_hex_editor_state() in ToolOutputPanel correctly create and distribute the state?

GUI PANEL (hex_editor/ directory):
- Does HexEditorPanel implement HexEditorPanelProtocol (tool_started, tool_closed, start_tool, stop_tool, load_file, goto_offset)?
- Does the hex view render bytes correctly (hex + ASCII columns)?
- Can the user edit bytes in-place?
- Does the cursor/selection system work?
- Does search (hex pattern, text, regex) work?
- Does the data inspector panel work (showing int8/16/32/64, float, double, etc. at cursor)?
- Does the pattern editor work (_pattern_editor.py)?
- Does the context push to AI (hex_context_ready signal) work?
- Does save/save-as work?
- Are large files handled efficiently (virtualized scrolling, not loading entire file into memory)?

WIRING:
- Does ToolRegistry.initialize() create HexEditorBridge and handle missing hexcore gracefully?
- Does add_hex_editor_tab() wire panel, bridge, and state correctly?
- Does the hex_context_ready signal reach the chat panel?
- Are all imports resolvable?

TYPE SAFETY:
- basedpyright compliance (especially around the native extension types)
- Protocol structural compatibility

OUTPUT FORMAT:
For each issue found, report:
- FILE: exact file path and line number(s)
- ISSUE: clear description of the problem
- SEVERITY: Critical / High / Medium / Low
- FIX: specific description of what needs to change

At the end, provide a prioritized fix plan grouping issues by file, ordered from Critical to Low.
```

---

## Prompt 6: Hex Tools

```
You are auditing the Hex Tools panel in the Intellicrack project (D:\Intellicrack) for end-to-end viability. This is a utility panel providing hex analysis operations. Your goal is to trace the ENTIRE pipeline, identify EVERY issue, and return a prioritized fix plan.

SCOPE - Read and analyze these files in full:

1. src/intellicrack/ui/panels/hex_tools_panel.py — the main Hex Tools panel
2. src/intellicrack/ui/tools.py — the add_hex_tools_tab() method and any HexTools protocols
3. src/intellicrack/ui/app.py — how the hex tools tab gets created
4. src/intellicrack/bridges/hex_editor.py — check if hex tools uses the hex editor bridge
5. src/intellicrack/bridges/hex_state.py — check if hex tools shares state with hex editor
6. src/intellicrack/core/tools.py — check if hex tools has its own registry entry
7. src/intellicrack/ui/panels/__init__.py — export validation
8. Any other files that hex_tools_panel.py imports from within the project

WHAT TO CHECK:

PANEL FUNCTIONALITY:
- What analysis operations does Hex Tools provide? (entropy visualization, string extraction, binary comparison, format detection, data conversion, encoding/decoding, etc.)
- Does each operation actually work against real binary data?
- Are the underlying analysis functions real implementations or stubs?
- Does the panel correctly receive binary data to analyze (from hex editor, from file, from loaded binary)?

INTEGRATION WITH HEX EDITOR:
- Does Hex Tools integrate with the Hex Editor panel (shared state, cursor position, selection)?
- Can Hex Tools operate on the currently loaded file in the hex editor?
- If they are independent, does Hex Tools have its own file loading mechanism?

UI QUALITY:
- Are all UI elements functional (buttons trigger actions, results display correctly)?
- Does the panel handle errors gracefully?
- Are Qt signals/slots correctly wired?
- Does the panel handle edge cases (no file loaded, empty selection, very large files)?

WIRING:
- Does add_hex_tools_tab() in ToolOutputPanel work correctly?
- Are all imports resolvable?
- Are there any circular import issues?

TYPE SAFETY:
- basedpyright compliance
- Complete type annotations

OUTPUT FORMAT:
For each issue found, report:
- FILE: exact file path and line number(s)
- ISSUE: clear description of the problem
- SEVERITY: Critical / High / Medium / Low
- FIX: specific description of what needs to change

At the end, provide a prioritized fix plan grouping issues by file, ordered from Critical to Low.
```

---

## Prompt 7: Binary

```
You are auditing the Binary analysis panel in the Intellicrack project (D:\Intellicrack) for end-to-end viability. This panel handles PE/ELF/Mach-O binary parsing using pefile and LIEF. Your goal is to trace the ENTIRE pipeline from bridge through GUI panel, identify EVERY issue, and return a prioritized fix plan.

SCOPE - Read and analyze these files in full:

1. src/intellicrack/bridges/base.py — specifically BinaryOperationsBridge and ToolBridgeBase
2. src/intellicrack/bridges/binary.py — the BinaryBridge implementation
3. src/intellicrack/ui/panels/binary_panel.py — the GUI panel
4. src/intellicrack/ui/tools.py — the BinaryPanelProtocol and add_binary_tab() wiring
5. src/intellicrack/core/tools.py — ToolRegistry registration and get_binary_bridge()
6. src/intellicrack/core/disassembler.py — the Capstone disassembler module used by binary analysis
7. src/intellicrack/core/yara_scanner.py — YARA scanning integration
8. src/intellicrack/core/orchestrator.py — orchestrator methods using the binary bridge
9. src/intellicrack/ui/app.py — how the binary tab gets created
10. src/intellicrack/bridges/__init__.py and src/intellicrack/ui/panels/__init__.py — export validation

WHAT TO CHECK at each layer:

BRIDGE LAYER (binary.py):
- Does BinaryBridge correctly inherit from BinaryOperationsBridge?
- Are ALL abstract methods from the base class implemented?
- Are pefile and lief imported and used correctly?
- Does initialize() work without requiring external tools?
- Do all operations work correctly:
  - parse_binary: correctly detect and parse PE/ELF/Mach-O formats
  - get_sections: enumerate all sections with correct attributes (name, virtual address, size, characteristics)
  - get_imports/get_exports: correctly extract import/export tables for all formats
  - get_strings: extract ASCII and Unicode strings with configurable minimum length
  - get_entropy: calculate per-section and overall entropy
  - patch_binary: write bytes at offset or RVA correctly, handling section boundaries
  - calculate_checksum: compute correct PE checksum
  - detect_architecture: correctly identify arch from headers
- Does the bridge handle packed/obfuscated binaries gracefully (malformed headers, overlay data, unusual section layouts)?
- Are tool_definitions correct?
- Error handling: corrupt binaries, unsupported formats, permission denied, file locked?

GUI PANEL (binary_panel.py):
- Does BinaryPanel implement BinaryPanelProtocol (tool_started, tool_closed, start_tool, stop_tool, load_file)?
- Does the panel display: file headers, sections table, imports/exports trees, strings list, entropy graph, hex preview?
- Can the user apply patches from the panel?
- Does the panel correctly load and display results for PE, ELF, and Mach-O binaries?
- Are Qt signals/slots correctly connected?
- Does the panel handle errors gracefully?

DISASSEMBLER INTEGRATION:
- Does core/disassembler.py correctly use Capstone?
- Can the binary panel request disassembly of specific sections/functions?
- Is architecture auto-detection correct (x86, x64, ARM, ARM64)?

WIRING:
- Does ToolRegistry.initialize() create BinaryBridge correctly?
- Does add_binary_tab() wire everything together?
- Does the orchestrator use binary bridge correctly for analysis workflows?
- Are all imports resolvable?

TYPE SAFETY:
- basedpyright compliance (pefile and lief have varying type stub quality)
- Protocol structural compatibility

OUTPUT FORMAT:
For each issue found, report:
- FILE: exact file path and line number(s)
- ISSUE: clear description of the problem
- SEVERITY: Critical / High / Medium / Low
- FIX: specific description of what needs to change

At the end, provide a prioritized fix plan grouping issues by file, ordered from Critical to Low.
```

---

## Prompt 8: Process

```
You are auditing the Process management panel in the Intellicrack project (D:\Intellicrack) for end-to-end viability. This panel handles Windows process attachment, memory read/write, and DLL injection. Your goal is to trace the ENTIRE pipeline from bridge through GUI panel, identify EVERY issue, and return a prioritized fix plan.

SCOPE - Read and analyze these files in full:

1. src/intellicrack/bridges/base.py — ToolBridgeBase (ProcessBridge's parent)
2. src/intellicrack/bridges/process.py — the ProcessBridge implementation
3. src/intellicrack/ui/panels/process_panel.py — the GUI panel
4. src/intellicrack/ui/tools.py — the ProcessPanelProtocol and add_process_tab() wiring
5. src/intellicrack/core/tools.py — ToolRegistry registration and get_process_bridge()
6. src/intellicrack/core/orchestrator.py — orchestrator methods using process bridge
7. src/intellicrack/ui/app.py — how the process tab gets created
8. src/intellicrack/bridges/__init__.py and src/intellicrack/ui/panels/__init__.py — export validation

WHAT TO CHECK at each layer:

BRIDGE LAYER (process.py):
- Does ProcessBridge correctly inherit from ToolBridgeBase?
- Are ALL abstract methods implemented?
- Does initialize() work on Windows (ctypes kernel32/psapi loading)?
- Does process enumeration work correctly (EnumProcesses or CreateToolhelp32Snapshot)?
- Do all process operations work:
  - enumerate_processes: list all running processes with PID, name, path
  - open_process: OpenProcess with appropriate access rights (PROCESS_ALL_ACCESS, PROCESS_VM_READ, etc.)
  - read_memory: ReadProcessMemory with correct buffer handling
  - write_memory: WriteProcessMemory with correct size validation
  - allocate_memory: VirtualAllocEx with correct protection flags
  - free_memory: VirtualFreeEx
  - protect_memory: VirtualProtectEx
  - inject_dll: CreateRemoteThread + LoadLibraryA/W injection
  - enumerate_threads: thread enumeration for the target process
  - enumerate_modules: module listing with base addresses and sizes
  - terminate_process: TerminateProcess
- Are Windows API constants correct (PAGE_EXECUTE_READWRITE, MEM_COMMIT, etc.)?
- Are ctypes structures and function signatures correct?
- Are handles properly closed (CloseHandle) to prevent handle leaks?
- Does the bridge handle: access denied (non-admin), 32-bit vs 64-bit process mismatch, system processes, process exit during operation?
- Are tool_definitions correct?
- Platform check: does it gracefully fail on non-Windows?

GUI PANEL (process_panel.py):
- Does ProcessPanel implement ProcessPanelProtocol (tool_started, tool_closed, start_tool, stop_tool, process_attached signal, get_selected_pid)?
- Does the panel display: process list (PID, name, arch, path), memory map, module list?
- Can the user: select a process, attach, read memory at address, write memory, inject DLL?
- Does the process list refresh?
- Does the process_attached signal fire correctly when a process is selected?
- Are Qt signals/slots correctly connected?
- Does the panel handle errors gracefully (access denied shown to user, not crash)?

WIRING:
- Does ToolRegistry.initialize() create ProcessBridge correctly?
- Does add_process_tab() wire everything together?
- Does the orchestrator use process bridge correctly?
- Does the process panel interact correctly with Frida panel (sharing PID)?
- Are all imports resolvable?

TYPE SAFETY:
- basedpyright compliance (ctypes typing is notoriously tricky)
- Protocol structural compatibility
- Windows-specific type handling (HANDLE, DWORD, LPVOID, etc.)

SECURITY:
- Are there any privilege escalation risks in the implementation?
- Does the bridge require admin elevation and handle the non-admin case?

OUTPUT FORMAT:
For each issue found, report:
- FILE: exact file path and line number(s)
- ISSUE: clear description of the problem
- SEVERITY: Critical / High / Medium / Low
- FIX: specific description of what needs to change

At the end, provide a prioritized fix plan grouping issues by file, ordered from Critical to Low.
```

---

## Prompt 9: Sandbox

```
You are auditing the Sandbox integration in the Intellicrack project (D:\Intellicrack) for end-to-end viability. This covers both Windows Sandbox and QEMU backends. Your goal is to trace the ENTIRE pipeline from sandbox backends through the bridge through to the GUI panel, identify EVERY issue, and return a prioritized fix plan.

SCOPE - Read and analyze these files in full:

1. src/intellicrack/bridges/base.py — ToolBridgeBase (SandboxBridge's parent)
2. src/intellicrack/bridges/sandbox_bridge.py — the SandboxBridge implementation
3. src/intellicrack/sandbox/ — the ENTIRE directory:
   - __init__.py
   - base.py — SandboxBase abstract class
   - manager.py — SandboxManager orchestration
   - windows.py — Windows Sandbox backend
   - qemu.py — QEMU backend
   - Any other files in this directory
4. src/intellicrack/ui/panels/sandbox_panel.py — the GUI panel
5. src/intellicrack/ui/sandbox_config.py — sandbox configuration dialog (SandboxConfigDialog, SandboxMonitorWidget)
6. src/intellicrack/ui/tools.py — SandboxPanelProtocol, add_sandbox_tab(), wire_sandbox_backend()
7. src/intellicrack/core/tools.py — ToolRegistry registration and get_sandbox_bridge()
8. src/intellicrack/ui/panels/vnc_widget.py — VNC widget for QEMU display
9. src/intellicrack/core/orchestrator.py — orchestrator methods using sandbox
10. src/intellicrack/ui/app.py — how the sandbox tab gets created
11. src/intellicrack/bridges/__init__.py, src/intellicrack/sandbox/__init__.py, src/intellicrack/ui/panels/__init__.py — export validation

WHAT TO CHECK at each layer:

SANDBOX BACKENDS:

Windows Sandbox (windows.py):
- Does it correctly detect Windows Sandbox availability (feature enabled, Windows 10/11 Pro/Enterprise)?
- Does it generate valid .wsb configuration files?
- Does it launch Windows Sandbox with the correct configuration?
- Does it copy the target binary into the sandbox?
- Does it monitor sandbox execution (process activity, file changes, registry changes, network)?
- Does it collect results after execution?
- Does it handle sandbox timeout and forced termination?
- Does cleanup work correctly?

QEMU (qemu.py):
- Does it correctly detect QEMU installation?
- Does it manage VM images (create, snapshot, restore)?
- Does it launch QEMU with correct parameters (KVM/WHPX acceleration, networking, shared folder)?
- Does it support multiple guest OS types?
- Does it handle VNC/SPICE display connection for the VNC widget?
- Does it transfer files into/out of the VM?
- Does it monitor guest execution?
- Does snapshot/restore work?
- Does cleanup (VM shutdown, temporary file removal) work?

SANDBOX MANAGER (manager.py):
- Does SandboxManager correctly select between Windows Sandbox and QEMU backends?
- Does it handle backend availability detection?
- Does it manage concurrent sandbox sessions?
- Does it aggregate results from different backends?

BRIDGE LAYER (sandbox_bridge.py):
- Does SandboxBridge correctly inherit from ToolBridgeBase?
- Are ALL abstract methods implemented?
- Does it delegate correctly to the sandbox backends?
- Does initialize() detect available sandbox backends?
- Do all operations work: create_sandbox, execute_in_sandbox, get_results, destroy_sandbox?
- Are tool_definitions correct?
- Error handling: sandbox not available, execution failure, timeout?

GUI PANEL (sandbox_panel.py):
- Does SandboxPanel implement SandboxPanelProtocol (tool_started, tool_closed, start_tool, stop_tool, set_sandbox, get_sandbox, set_sandbox_manager)?
- Can the user: select a sandbox type, configure execution parameters, launch a binary, view execution results, see process/file/registry/network activity?
- Does the panel display execution progress?
- Does the panel show a VNC view for QEMU sessions?
- Are Qt signals/slots correctly connected?
- Does the panel handle errors gracefully?

SANDBOX CONFIG (sandbox_config.py):
- Does SandboxConfigDialog correctly detect sandbox availability?
- Does SandboxMonitorWidget display real-time monitoring data?
- Are these correctly wired into add_sandbox_tab()?

VNC WIDGET (vnc_widget.py):
- Does the VNC widget connect to QEMU's VNC server?
- Does it render the display correctly?
- Does it pass keyboard/mouse input?
- What VNC library does it use and is it correctly integrated?

WIRING:
- Does ToolRegistry.initialize() create SandboxBridge correctly?
- Does add_sandbox_tab() check sandbox availability before creating the tab?
- Does wire_sandbox_backend() correctly distribute the backend to the panel?
- Does the orchestrator use sandbox correctly?
- Are all imports resolvable?

TYPE SAFETY:
- basedpyright compliance across all sandbox modules
- Protocol structural compatibility

OUTPUT FORMAT:
For each issue found, report:
- FILE: exact file path and line number(s)
- ISSUE: clear description of the problem
- SEVERITY: Critical / High / Medium / Low
- FIX: specific description of what needs to change

At the end, provide a prioritized fix plan grouping issues by file, ordered from Critical to Low.
```

---

## Usage Instructions

1. Open a separate Claude conversation for each prompt
2. Copy-paste ONE prompt per conversation
3. Claude will read the specified files, trace the full pipeline, and return a detailed issue list with fix plan
4. Collect all 9 reports and use them to create a unified remediation plan
