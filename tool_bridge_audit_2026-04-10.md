# Intellicrack Tool Bridge Completeness Audit

**Date:** 2026-04-10
**Scope:** All 8 embedded tool bridges, GUI panel exposure, missing tool integrations
**Methodology:** Code-level analysis of bridge implementations, tool_definitions, GUI panels, and comparison against full external tool APIs

---

## Executive Summary

Intellicrack currently has **8 tool bridges** exposing **259 AI-callable tool functions** and **275+ bridge methods**. This audit found:

- **~400+ missing capabilities** across existing bridges where the underlying tool provides functionality not yet wrapped
- **164 of 259 AI tool functions (63%) have no GUI controls** - users cannot access them manually
- **3 bridges completely disconnected from GUI** (Binary, Process, Sandbox panels are independent implementations with zero shared state)
- **9 critical implementation bugs** that cause incorrect behavior
- **6+ external tools** with icons/assets in the codebase but no bridge implementation
- **13+ industry-standard RE tools** that should be considered for integration

### Gap Severity Distribution

| Bridge | Implemented | Missing Capabilities | Critical Bugs | GUI Coverage |
|--------|------------|---------------------|---------------|--------------|
| Ghidra | 36 AI tools | ~37 categories | 2 | 36% (13/36) |
| x64dbg | 48 AI tools | ~33 categories | 5 | 42% (20/48) |
| Frida | 36 AI tools | ~50+ categories | 2 | 39% (14/36) |
| Cutter | 21 AI tools | ~45+ categories | 3 | 62% (13/21) |
| HexEditor | 70 AI tools | ~15 categories | 0 | 50% (~35/70) |
| Binary | 17 AI tools | ~30+ categories | 2 | **0%** (disconnected) |
| Process | 17 AI tools | ~25+ categories | 0 | **0%** (disconnected) |
| Sandbox | 14 AI tools | ~20+ categories | 1 | **0%** (disconnected) |

---

## 1. GHIDRA

> Read all findings below for the Ghidra bridge (sections 1A through 1C). Create a plan covering the full end-to-end implementation of every bug fix, every missing capability, and every GUI panel gap listed. Each new bridge method must make real Ghidra API calls via the ghidra_bridge RPC, be registered in tool_definitions so the AI can call it, and have a corresponding GUI control in the Ghidra panel. Every item must be fully functional and production-release ready. No item may be deferred, stubbed, or skipped.

**File:** `src/intellicrack/bridges/ghidra.py` (2,640 lines)
**Panel:** `src/intellicrack/ui/panels/ghidra_panel.py` (795 lines)
**Communication:** ghidra_bridge RPC to Jython JVM on port 4768
**Panel Architecture:** Panel calls bridge methods directly (connected)

### 1A. Critical Bugs

1. **Wildcard byte search silently broken** - `search_bytes()` constructs a concrete byte array but passes `None` for the mask parameter to `getMemory().findBytes()`. Wildcard `??` patterns are accepted by the tool_definition but silently dropped - the search runs as an exact match.

2. **No memory read-back** - The bridge can `write_bytes()` but has no `read_bytes(address, length)` method. `Memory.getBytes()` is never called. The AI can write to the program but cannot read arbitrary bytes back programmatically.

### 1B. Missing Capabilities (37 categories)

**High Priority (core analysis workflows):**

| # | Capability | Ghidra API | Impact |
|---|-----------|------------|--------|
| 1 | PCode / Intermediate Representation | `HighFunction.getPcodeOps()`, `Varnode`, `PcodeBlockBasic` | Ghidra's most powerful IR, completely absent |
| 2 | Basic block CFG | `BasicBlockModel`, `CodeBlock.getSources/Destinations()` | No control flow graph at block level |
| 3 | Forward/backward slice | `ForwardSliceAnalysis`, `ProgramDependenceGraph` | No data-flow slice capability |
| 4 | Caller direction in call graph | Reverse traversal of `getReferencesTo()` | `get_call_graph` only traverses callees |
| 5 | Register value analysis | `ProgramContext.getRegisterValue()` | No assumed register value queries |
| 6 | Memory read-back | `Memory.getBytes()`, `getByte()`, `getInt()` | Can write but not read |
| 7 | DWARF/PDB debug info | `DWARFProgram`, `PdbUniversalAnalyzer` | No debug symbol import or access |
| 8 | Bookmark types | `BookmarkManager.defineType()` | Hardcoded to "Note" only |
| 9 | String encoding detection | `UnicodeDataType`, `Unicode32DataType` | Always returns encoding="ascii" |

**Medium Priority (achievable via `execute_script` workaround):**

| # | Capability | Ghidra API |
|---|-----------|------------|
| 10 | Reference creation/deletion | `ReferenceManager.addMemoryReference/delete()` |
| 11 | Namespace management | `getSymbolTable().createNameSpace()` |
| 12 | Equate management (constant naming) | `EquateTable.createEquate()` |
| 13 | External program manager | `ExternalManager.addExtFunction()` |
| 14 | Relocation table access | `RelocationTable.iterator()` |
| 15 | Full DataTypeManager ops | Enum/Union/Typedef/FunctionDef creation |
| 16 | Stack frame analysis | `Function.getStackFrame()`, `StackVariable` |
| 17 | Auto-analysis configuration | Per-analyzer enable/disable and options |
| 18 | Listing iteration | Bulk comment/data/instruction queries |
| 19 | Symbol table (beyond labels) | Full `SymbolType` discrimination and search |
| 20 | Decompiler options | `setSimplificationStyle()`, `setMaxInstructions()` |
| 21 | Memory block creation | `Memory.createInitializedBlock()`, split/join |
| 22 | Calling convention details | `CompilerSpec.getCallingConventions()` |
| 23 | Function body analysis | `isThunk()`, `getBody()` as AddressSetView |
| 24 | Call tree (callers) | Bidirectional call tree generation |
| 25 | Defined data creation | Array, pointer-to-type, string data |
| 26 | All comments read-back | `getCommentCodeUnitIterator()` |
| 27 | Instruction flow analysis | `getFlowType()`, `getFallThrough()`, `getFlows()` |

**Lower Priority (administrative/specialized):**

| # | Capability |
|---|-----------|
| 28 | Program tree / fragment management |
| 29 | Property management on code units |
| 30 | Version tracking / diff between programs |
| 31 | Color/highlighting management |
| 32 | Ghidra project management |
| 33 | Overlay address spaces |
| 34 | Program metadata write-back (rename, rebase) |
| 35 | Script execution with parameters |
| 36 | Thunk function management |
| 37 | External reference management |

### 1C. GUI Panel Gaps

**23 of 36 AI tools have no GUI controls (64% AI-only).**

Bridge methods with NO GUI surface: `search_bytes`, `rename_function`, `add_comment`, `get_data_type`, `set_data_type`, `execute_script`, `set_label`, `get_labels`, `create_bookmark`, `get_bookmarks`, `create_function`, `delete_function`, `edit_function_signature`, `set_function_variable_type`, `define_structure`, `get_structures`, `apply_structure_at`, `get_call_graph`, `get_segments`, `get_program_info`, `write_bytes`, `undo`, `redo`

---

## 2. X64DBG

> Read all findings below for the x64dbg bridge (sections 2A through 2C). Create a plan covering the full end-to-end implementation of every bug fix, every missing capability, and every GUI panel gap listed. Each new bridge method must communicate via the named pipe protocol to the C++ plugin (adding new plugin command handlers where needed), be registered in tool_definitions so the AI can call it, and have a corresponding GUI control in the x64dbg panel. Every item must be fully functional and production-release ready. No item may be deferred, stubbed, or skipped.

**File:** `src/intellicrack/bridges/x64dbg.py` (3,188 lines)
**Panel:** `src/intellicrack/ui/panels/x64dbg_panel.py` (1,219 lines)
**Communication:** Named pipe IPC to C++ plugin, Win32 API for memory ops
**Panel Architecture:** Panel calls bridge methods directly (connected)

### 2A. Critical Bugs

1. **Hardware breakpoints silently converted to software** - `set_breakpoint(bp_type="hardware")` sends `"bp_set"` to the C++ plugin which always issues INT3 software BPs. True hardware execution BPs require `bphws` which is never called for execution-type hardware BPs.

2. **`assemble_at` does not write bytes** - Assembles via Keystone and returns bytes but never writes them to process memory. The tool description implies the instruction is patched.

3. **Stack trace fails on x64 optimized code** - Uses manual RBP chain walk which produces no frames (or garbage) for nearly all real-world x64 targets compiled with omit-frame-pointer. The C++ plugin's `DbgStackTrace` equivalent would use x64 unwind information correctly but there is no `stack_trace` plugin command.

4. **Disassembly uses Capstone directly, not the plugin** - Output has no symbol names, labels, comments, or cross-reference decoration. The plugin's `disasm` command returns x64dbg-native decorated text but is unused.

5. **C++ plugin `mod_imports` fully implemented but no Python bridge method calls it** - The plugin-side `cmd_mod_imports` works but is completely unreachable from the bridge or AI.

6. **`spawn` is a dark method** - Defined on the bridge class (line 2373) but absent from BOTH tool_definitions AND GUI. Neither users nor AI can call it.

### 2B. Missing Capabilities (33 categories)

**High Priority:**

| # | Capability | x64dbg Feature |
|---|-----------|---------------|
| 1 | Reference searching | String refs, constant refs, call refs, intermodular calls |
| 2 | Expression evaluation | Full expression evaluator returning typed values |
| 3 | Graph/flowchart generation | CFG of function at address |
| 4 | Database save/load | `.dd64`/`.dd32` state persistence |
| 5 | Patch management | List/export/import/restore patches |
| 6 | Thread control | Freeze/thaw/switch/name individual threads |
| 7 | SEH/VEH chain walking | Exception handler chain inspection |
| 8 | PEB/TEB reading | Full structured PEB/TEB field access |
| 9 | Module imports | Plugin implements `mod_imports` but bridge doesn't call it |
| 10 | Assemble-and-write (atomic) | `patch_instruction()` and `nop_range()` |
| 11 | PE directory analysis | All PE directories (security, relocs, resources, debug, TLS, .NET, exception, load config) |
| 12 | Watch expressions | Add/remove/get watch expressions evaluated at each step |

**Medium Priority:**

| # | Capability |
|---|-----------|
| 13 | Logging breakpoints (non-stopping) |
| 14 | BP condition/log/command/hit-count configuration |
| 15 | DLL load/unload breakpoints |
| 16 | Trace into/over as distinct operations |
| 17 | Trace record reading |
| 18 | Step count (N instructions) |
| 19 | Animation (automated stepping with delay) |
| 20 | Pattern scanning with alignment |
| 21 | Entropy analysis |
| 22 | YARA scanning |
| 23 | Script engine (x64dbg scripting language) |
| 24 | Plugin management |
| 25 | Handle enumeration |
| 26 | Anti-debug detection and patching |
| 27 | Import reconstruction |
| 28 | Call stack via x64 unwind info |
| 29 | Status query (is running/paused/attached) |
| 30 | Goto/navigate (scroll GUI to address) |
| 31 | TLS callback debugging |
| 32 | Resource viewer |
| 33 | Privilege management |

### 2C. GUI Panel Gaps

**28 of 48 AI tools have no GUI controls (58% AI-only).**

Panel does NOT expose controls for: `detach`, `write_memory`, `find_pattern`, `set_watchpoint`, `remove_watchpoint`, `get_watchpoints`, `allocate_memory`, `free_memory`, `assemble_at`, `scan_memory`, `get_process_info`, `get_memory_regions`, `run_to`, `execute_til_return`, `skip_instruction`, `set_ip`, `set_label`, `get_labels`, `set_comment`, `get_comments`, `enable_breakpoint`, `disable_breakpoint`, `set_breakpoint_on_api`, `dump_memory_to_file`, `get_module_sections`, `get_module_exports`, `trace_start`, `trace_stop`, `set_exception_config`

---

## 3. FRIDA

> Read all findings below for the Frida bridge (sections 3A through 3C). Create a plan covering the full end-to-end implementation of every bug fix, every missing capability (including all missing subsystems), and every GUI panel gap listed. Each new bridge method must use real Frida Python API calls and/or inject working JavaScript into the target, be registered in tool_definitions so the AI can call it, and have a corresponding GUI control in the Frida panel (including new tabs for memory, modules, and symbols where needed). Every item must be fully functional and production-release ready. No item may be deferred, stubbed, or skipped.

**File:** `src/intellicrack/bridges/frida_bridge.py` (2,417 lines)
**Panel:** `src/intellicrack/ui/panels/frida_panel.py` (1,075 lines)
**Communication:** frida-python library + injected JavaScript
**Panel Architecture:** Panel calls bridge methods directly (connected)

### 3A. Critical Bugs

1. **`call_function` hardcodes all types to `'pointer'`** - `NativeFunction(ptr, 'pointer', [...'pointer'...])` fails for any real-world function taking integers, returning void, or using non-default calling conventions.

2. **`scan_memory` misses code pages** - Uses `Process.enumerateRanges('r--')` which excludes `r-x` (executable) and `rw-` pages. Pattern searches in code sections find nothing.

### 3B. Missing Capabilities (50+ categories)

**Entire Subsystems Missing:**

| Subsystem | Capabilities |
|-----------|-------------|
| **ObjC Bridge** | `ObjC.classes`, `ObjC.protocols`, `ObjC.Object`, `ObjC.enumerateLoadedClasses`, `ObjC.choose`, class registration. Blocks all macOS/iOS analysis. |
| **Java Bridge** | `Java.perform`, `Java.use`, `Java.choose`, `Java.cast`, `Java.registerClass`, `Java.deoptimizeEverything`, `Java.enumerateLoadedClasses`. Blocks all Android analysis. |
| **CModule** | `new CModule(code)` - inline C compilation in target process. Essential for performance-critical instrumentation. |
| **Kernel API** | `Kernel.available/base/pageSize`, enumerate modules/ranges, alloc/protect, read/write kernel memory. |
| **Socket API** | `Socket.listen`, `Socket.connect`, socket inspection from inside target. |
| **File API** | `new File(path, mode)` - filesystem access from within target process. |
| **SqliteDatabase** | `SqliteDatabase.open`, `.exec`, `.dump` - database access from target. |
| **Code Writers** | `X86Writer`, `ArmWriter`, `Arm64Writer`, `ThumbWriter`, `MipsWriter` - code generation APIs. |
| **Cloak** | Thread and memory range cloaking for anti-detection. |
| **TypeScript Compiler** | `frida.Compiler` for TypeScript source compilation before injection. |
| **FileMonitor** | `frida.FileMonitor` for filesystem change monitoring. |

**Individual Missing Capabilities:**

| # | Capability | Impact |
|---|-----------|--------|
| 1 | `script.post()` - Python-to-script messages | No bidirectional RPC possible |
| 2 | `script.eternalize()` | Persistent scripts without Python reference |
| 3 | `rpc.exports` pattern | Cannot call script-side functions from Python |
| 4 | `Module.enumerateSymbols()` | Full symbol table (not just exports/imports) |
| 5 | `Module.load(path)` | Load additional shared library into target |
| 6 | `Memory.patchCode()` | Safe code patching with cache flush |
| 7 | `Memory.allocUtf8/Ansi/Utf16String()` | String allocation in target |
| 8 | `Thread.backtrace()` | Stack traces in hooks |
| 9 | `Process.setExceptionHandler()` | In-process crash interception |
| 10 | `Process.findModuleByAddress()` | Module-from-address lookup |
| 11 | `DebugSymbol.findFunctionsMatching(glob)` | Glob pattern symbol search |
| 12 | `Instruction.parse(address)` | Single instruction disassembly |
| 13 | `device.enumerate_applications()` | Mobile app listing |
| 14 | `device.inject_library_file/blob()` | Native library injection |
| 15 | `Stalker.addCallProbe()` | Targeted call tracing |
| 16 | `Interceptor.revert()` | Revert specific hook |
| 17 | `Interceptor.flush()` | Force buffered data send |
| 18 | `SystemFunction` (captures errno/GetLastError) | Error-aware native calls |
| 19 | Calling convention specification | thiscall, fastcall, sysv64, etc. |
| 20 | `frida.Cancellable` | Cancel long-running operations |
| 21 | `ApiResolver` type parameter | Only `'module'` is reachable, not `'objc'` or `'swift'` |

### 3C. GUI Panel Gaps

**22 of 36 AI tools have no GUI controls (61% AI-only).**

Panel does NOT expose: `spawn`, `resume`, `enumerate_modules`, `enumerate_exports`, `enumerate_imports`, `read_memory`, `write_memory`, `scan_memory`, `execute_script` (one-shot), `intercept_return`, `call_function`, `get_memory_regions`, `allocate_memory`, `get_hooks`, `protect_memory`, `find_base_address`, `resolve_symbol`, `find_functions_named`, `resolve_api`, `replace_function`, `enable_child_gating`, `disable_child_gating`, `get_pending_children`, `resume_child`, `enable_crash_reporting`, `get_crashes`

Stalker UI missing `compile` event checkbox.

---

## 4. CUTTER / RIZIN

> Read all findings below for the Cutter/Rizin bridge (sections 4A through 4C). Create a plan covering the full end-to-end implementation of every bug fix, every missing capability, and every GUI panel gap listed. Each new bridge method must send real Rizin r2pipe commands and parse their JSON output, be registered in tool_definitions so the AI can call it, and have a corresponding GUI control in the Cutter panel. Every item must be fully functional and production-release ready. No item may be deferred, stubbed, or skipped.

**File:** `src/intellicrack/bridges/cutter.py` (1,487 lines)
**Panel:** `src/intellicrack/ui/panels/cutter_panel.py` (914 lines)
**Communication:** r2pipe to Rizin/Cutter
**Panel Architecture:** Panel calls bridge methods directly (connected)

### 4A. Critical Bugs

1. **`assemble_at()` calls `rasm2` via r2pipe** - `rasm2` is a standalone CLI tool, not an r2pipe command. The correct r2pipe command is `pa instruction` or `!rasm2 ...` with shell escape.

2. **Entry point calculation double-adds baddr** - `bin.entry` from `ij` is already the absolute VA; adding `baddr` again produces wrong addresses.

3. **No save/flush mechanism** - `io.cache=true` is set but no `save_binary()` method exists. Patches via `write_bytes`/`assemble_at` are lost on close. Need `wtf filename` to flush.

### 4B. Missing Capabilities (45+ categories)

**High Priority:**

| # | Capability | Rizin Commands |
|---|-----------|---------------|
| 1 | `get_function_graph` not in tool_definition | `agj` - implemented but not AI-exposed |
| 2 | All-strings (not just data sections) | `izzj` |
| 3 | Symbol table (distinct from exports) | `isj` |
| 4 | Libraries list | `ilj` |
| 5 | Header fields | `ihj`, `iHj` |
| 6 | Debug info | `iDj` |
| 7 | C++/ObjC/Java classes | `icj`, `iccj` |
| 8 | Relocations | `iRj` |
| 9 | Resources (PE resources) | `irj` |
| 10 | ROP gadget search | `/Rj`, `/Rkj` |
| 11 | Whole-program callgraph | `agcj` |
| 12 | Vtable analysis | `avj` |
| 13 | Syscall analysis | `asj` |
| 14 | Read raw bytes | `p8 N @ addr` |
| 15 | Save patched binary | `wtf path` |
| 16 | All comments read-back | `CCj` |
| 17 | Flags/labels system | `fj`, `f name @ addr`, `fd addr` |

**Medium Priority - Entire Subsystems:**

| Subsystem | Rizin Commands |
|-----------|---------------|
| Type system | `tdj`, `tsj`, `tuj`, `tej`, `tfj`, `tlj`, `to` (C header import) |
| ESIL emulation | `ae`, `aes`, `aef`, `aeim`, `aeip` |
| Zignatures (FLIRT-like) | `zj`, `zg`, `za`, `zoj` |
| Project management | `Psj`, `Poj`, `Plj` |
| Configuration | `e key`, `e key=value` |
| Write operations | `wox`, `woa`, `wos` (XOR/ADD/SUB), `wf`, `wt`, `wv`, `wz` |
| Search capabilities | `/j` (live string search), `/aj` (assembly pattern), `/cej` (crypto detection), `/mj` (magic), `/vj` (value search) |
| Comparison/diff | `cj`, `cdj` |
| ELF segments | `iSSj` |
| Hexdump | `pxj`, `pxwj`, `pdfj` (full function disasm) |
| Function basic blocks | `afbj` |

### 4C. GUI Panel Gaps

**8 of 21 AI tools have no GUI controls (38% AI-only).**

Panel has no UI for: `search_bytes`, `search_bytes_wildcard`, `rename_function`, `add_comment`, `write_bytes`, `get_function` (by address), `assemble_at`, `seek`, `get_function_address`

Panel also has no all-strings view without a search pattern.

---

## 5. HEX EDITOR

> Read all findings below for the Hex Editor bridge (sections 5A through 5C). Create a plan covering the full end-to-end implementation of every missing capability and every GUI panel gap listed. Each new bridge method must operate on the real Rust hexcore document model (extending the Rust crate if needed), be registered in tool_definitions so the AI can call it, and have a corresponding GUI control in the hex editor panel. Every item must be fully functional and production-release ready. No item may be deferred, stubbed, or skipped.

**File:** `src/intellicrack/bridges/hex_editor.py`
**Panel:** `src/intellicrack/ui/panels/hex_editor/panel.py`
**Communication:** Direct Rust hexcore document model
**Panel Architecture:** Shared state via HexDocumentState (connected)
**Status:** Most complete bridge at 70 AI tools and 80+ methods

### 5A. Critical Bugs

None found.

### 5B. Missing Capabilities (15 categories)

| # | Capability | Description |
|---|-----------|-------------|
| 1 | BPS/UPS patch formats | Only IPS/IPS32 supported |
| 2 | Block operations | No fill_block, copy_block, move_block, swap_block |
| 3 | Binary arithmetic on selections | No in-place XOR/AND/OR/NOT/shift/rotate across selection |
| 4 | Virtual address mapping | No persistent VA overlay on hex view |
| 5 | String table catalog | No `get_strings()` method for full document string extraction |
| 6 | PE/ELF structure overlay | No permanent navigable structure bookmarks |
| 7 | Bit-level editing | Smallest unit is one byte |
| 8 | Annotated export formats | No HTML/PDF hex dump report |
| 9 | Sector/cluster alignment | No alignment snap tools |
| 10 | Checksum verification/repair | Calculate but no auto-repair of PE/ELF checksum fields |
| 11 | Base conversion calculator | Standalone base converter |
| 12 | Python scripting | Only HexPat scripting, no Python macro API |
| 13 | Large file controls | No explicit chunk size/prefetch hints for >4GB files |
| 14 | Color mapping modes | No entropy heatmap, structure coloring by template |
| 15 | Non-YARA signature databases | No DIE/ClamAV/custom signature scanning |

### 5C. GUI Panel Gaps

**~35 of 70 AI tools have no GUI controls (50% AI-only).**

AI-only functions with no panel surface: `save_to_sandbox`, `test_in_sandbox`, `compare_files`, `copy_as`, `get_byte_statistics` (programmatic), `get_entropy` (programmatic), `get_entropy_map`, `get_byte_distribution` (programmatic), `get_byte_type_distribution`, `get_digram_matrix`, `get_content_classification`, `get_document_info`, `get_context_for_ai`, `calculate_hash_range`, `calculate_hash_custom_crc`, `list_encodings`, `decode_text`, `encode_text`, `set_display_mode`, `get_display_mode`, `add_highlight_rule`, `remove_highlight_rule`, `list_highlight_rules`, `list_process_regions`, `open_process_memory`, advanced template management (register/remove/export/compile/execute pattern)

---

## 7. PROCESS

> Read all findings below for the Process bridge (sections 7A through 7C). Create a plan covering the full end-to-end implementation of every missing capability, every GUI panel gap, and the architectural unification of ProcessPanel with ProcessBridge (eliminating the disconnected parallel implementation so GUI and AI share one code path). Each new bridge method must use real Win32 ctypes and NtDll APIs, be registered in tool_definitions so the AI can call it, and have a corresponding GUI control in the unified Process panel. Every item must be fully functional and production-release ready. No item may be deferred, stubbed, or skipped.

**File:** `src/intellicrack/bridges/process.py`
**Panel:** `src/intellicrack/ui/panels/process_panel.py`
**Communication:** Win32 API (ctypes)
**Panel Architecture:** **DISCONNECTED** - ProcessPanel uses raw Win32 ctypes directly with its own process enumeration. Zero shared state with ProcessBridge. Panel has terminate; bridge has suspend/resume. They are parallel implementations.

### 7A. Critical Bugs

None found (but thread `start_address` is always hardcoded to 0 and `state` is always "unknown").

### 7B. Missing Capabilities (25+ categories)

| # | Capability | Win32 API |
|---|-----------|----------|
| 1 | Token/privilege manipulation | `OpenProcessToken`, `AdjustTokenPrivileges` |
| 2 | Handle enumeration | `NtQuerySystemInformation(SystemHandleInformation)` |
| 3 | Window enumeration | `EnumWindows`, `GetWindowThreadProcessId` |
| 4 | Service management | `OpenSCManager`, `EnumServicesStatusEx` |
| 5 | PEB/TEB access | Process Environment Block (image base, loader, cmdline) |
| 6 | Heap enumeration | `Heap32ListFirst/Next`, heap walking |
| 7 | Debug privilege auto-elevation | `SeDebugPrivilege` escalation |
| 8 | Thread context (registers) | `GetThreadContext` / `SetThreadContext` |
| 9 | Thread start address | `NtQueryInformationThread` (currently hardcoded 0) |
| 10 | Stack walk with symbols | `StackWalk64`, `SymFromAddr` via DbgHelp |
| 11 | Exception handler chain | SEH chain via TEB, VEH enumeration |
| 12 | Memory-mapped file regions | `GetMappedFileName` for MEM_MAPPED |
| 13 | Named pipe operations | IPC pipe enumeration and interaction |
| 14 | COM object enumeration | COM apartment/server queries |
| 15 | .NET CLR inspection | AppDomain, managed heap |
| 16 | Driver communication | `DeviceIoControl` |
| 17 | Process mitigation policies | `GetProcessMitigationPolicy` |
| 18 | Environment variable access | PEB environment block |
| 19 | Job object management | Job assignment and limits |
| 20 | GDI/User object enumeration | `GetGuiResources` |
| 21 | Registry access | Process registry view |
| 22 | Section object mapping | File mapping operations |
| 23 | TLS slot access | Thread-local storage values |
| 24 | Fiber enumeration | Windows fiber/coroutine listing |
| 25 | NtQuerySystemInformation | Direct NtDll bridge |

### 7C. GUI Panel Gaps

**17 of 17 AI tools have no GUI controls (100% AI-only).**

The ProcessPanel never calls any ProcessBridge method. All 17 AI tool functions (`list`, `open`, `close`, `terminate`, `suspend`, `resume`, `read_memory`, `write_memory`, `allocate`, `free`, `protect`, `get_modules`, `get_threads`, `get_memory_map`, `search_pattern`, `inject_dll`, `get_process_info`) are accessible only to the AI.

Panel has no controls for: `suspend`, `resume`, `read_memory`, `write_memory`, `allocate`, `free`, `protect`, `search_pattern`, `inject_dll`, `get_memory_map`.

---

## 8. SANDBOX

> Read all findings below for the Sandbox bridge (sections 8A through 8C). Create a plan covering the full end-to-end implementation of every bug fix, every missing capability, every GUI panel gap, and the architectural unification of SandboxPanel with SandboxBridge (eliminating the disconnected parallel implementation so GUI and AI share one code path). Each new bridge method must perform real sandbox operations via SandboxManager/QEMU QMP, be registered in tool_definitions so the AI can call it, and have a corresponding GUI control in the unified Sandbox panel. Every item must be fully functional and production-release ready. No item may be deferred, stubbed, or skipped.

**File:** `src/intellicrack/bridges/sandbox_bridge.py`
**Panel:** `src/intellicrack/ui/panels/sandbox_panel.py`
**Communication:** SandboxManager (Windows Sandbox / QEMU backends)
**Panel Architecture:** **DISCONNECTED** - SandboxPanel uses SandboxBase/SandboxManager directly, not SandboxBridge. The bridge is purely an AI interface. `cont` and `get_pending_messages` have no GUI equivalent at all.

### 8A. Critical Bugs

1. **Timeout parameter name mismatch** - tool_definition uses `timeout` but method signature uses `max_wait`. Parameters may be silently ignored during AI dispatch.

2. **Docker sandbox type inconsistency** - HexEditorBridge's `save_to_sandbox`/`test_in_sandbox` passes `sandbox_type="docker"` but `SandboxType` only supports `"windows"` and `"qemu"`. Non-"windows" values silently map to "qemu". No Docker backend exists.

### 8B. Missing Capabilities (20+ categories)

| # | Capability | Description |
|---|-----------|-------------|
| 1 | PCAP network capture | Capture + export raw network traffic |
| 2 | Screenshot capture | QEMU `screendump` or equivalent |
| 3 | API call logging/tracing | ETW or Detours-style call logging |
| 4 | Anti-evasion / sandbox hardening | Hide sandbox indicators |
| 5 | Memory dump extraction | Full guest memory dump at specific points |
| 6 | Detailed registry monitoring | Key, value, old/new, operation type |
| 7 | Service creation monitoring | Detect service installation |
| 8 | Mutex/event monitoring | Named kernel object creation tracking |
| 9 | DLL load tracking | Ordered DLL load list with timestamps |
| 10 | Dropped file extraction | Bulk copy-out of all created files |
| 11 | C2 communication detection | Network heuristics / Suricata rules |
| 12 | YARA scanning of artifacts | Scan sandbox filesystem/memory with YARA |
| 13 | IOC extraction | Structured indicators (IPs, domains, hashes, mutexes) |
| 14 | Timeline generation | Chronological event correlation |
| 15 | Behavioral signatures | Rule-based behavior classification |
| 16 | Process injection detection | Detect hollowing, remote thread, APC injection |
| 17 | Sandbox diff (between runs) | Compare two execution reports |
| 18 | Resource monitoring | CPU, memory, disk I/O metrics |
| 19 | Clipboard monitoring | Clipboard operation tracking |

### 8C. GUI Panel Gaps

**14 of 14 AI tools have no GUI controls (100% AI-only).**

The SandboxPanel uses SandboxBase/SandboxManager directly. All 14 SandboxBridge AI tool functions (`create`, `destroy`, `run_binary`, `execute`, `copy_to`, `copy_from`, `status`, `list`, `snapshot_create`, `snapshot_restore`, `snapshot_list`, `snapshot_delete`, `cont`, `get_pending_messages`) are accessible only to the AI.

---

## Appendix: Overall Statistics

| Bridge | Public Methods | AI Tool Functions | GUI-Exposed | AI-Only | Dark | Panel Architecture |
|--------|---------------|-------------------|-------------|---------|------|--------------------|
| Ghidra | ~30 | 36 | 13 | 23 | ~8 | Connected (direct bridge calls) |
| x64dbg | ~35 | 48 | 20 | 28 | 1 (`spawn`) | Connected (direct bridge calls) |
| Frida | ~30 | 36 | 14 | 22 | ~5 | Connected (direct bridge calls) |
| Cutter | ~25 | 21 | 13 | 8 | ~8 | Connected (direct bridge calls) |
| HexEditor | ~80 | 70 | ~35 | ~35 | ~15 | Connected (shared state via HexDocumentState) |
| Binary | ~18 | 17 | **0** | **17** | ~8 | **DISCONNECTED** |
| Process | ~15 | 17 | **0** | **17** | ~5 | **DISCONNECTED** |
| Sandbox | ~12 | 14 | **0** | **14** | ~2 | **DISCONNECTED** |
| **Total** | **~275** | **259** | **~95** | **~164** | **~52** | 3 disconnected, 5 connected |

**Key finding: 63% of all AI tool functions have no GUI controls** (164 of 259). For the 3 disconnected bridges, that figure is 100%.
