# Section 02 — Disassembler / RE-Tool Bridges: Test Coverage Audit

**Date:** 2026-06-26  
**Auditor:** test-reviewer (adversarial, not charitable)  
**Scope:**  
- `src/intellicrack/bridges/ghidra.py` (311 KB, ~8000 lines; 81 tool-definition functions)  
- `src/intellicrack/bridges/cutter.py` (4574 lines; 95 tool-definition functions + 2 public utilities)  
- `src/intellicrack/core/disassembler.py` (427 lines; 9 public operations)  

**Test files examined:**  
- `tests/test_bridges/test_ghidra.py` (1416 lines)  
- `tests/test_bridges/test_cutter.py` (1638 lines)  
- `tests/test_bridges/test_realcov_03b_ghidra.py` (584 lines)  
- `tests/test_bridges/test_ghidra_f11_audit.py` (172 lines)  
- `tests/test_bridges/test_ghidra_audit6.py` (2746 lines)  
- `tests/test_audit3/core/test_disassembler.py` (298 lines)  
- `tests/test_audit3/ui/test_ghidra_panel.py` (268 lines)  
- `tests/test_audit4/c9_hex_disassembly_debounce/test_realcov_13a_disassembly_output.py` (233 lines)  
- `tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py` (1010 lines)  
- `tests/test_core/test_realcov_07a_disassembler.py` (401 lines)  
- `tests/test_hexcore_e2e/test_bridge_disassembly.py` (196 lines)  
- `tests/test_hexcore_e2e/test_bridge_disassembly_deep.py` (308 lines)  
- `tests/test_ui/test_realcov_14b_cutter_tabs.py` (313 lines)  

**Verdict key:**  
- `REAL` — asserts specific values from an independent oracle; breaks if production code is deleted or corrupted  
- `WEAK` — asserts only existence/type/non-emptiness; would not catch value-level regressions  
- `FAKE` — test passes even when the operation is broken; forbidden anti-pattern present  
- `NONE` — zero test coverage  

---

## 1. Operation Inventory

### 1.1 `src/intellicrack/core/disassembler.py`

| Operation | Source line | Test(s) | Verdict | Missing edges |
|---|---|---|---|---|
| `_to_disassembly_line(insn)` | ~65 | test_realcov_07a:264–285 (field-by-field vs. `disassemble()` output) | REAL | — |
| `UnsupportedArchitectureError.arch` attribute | ~55 | test_disassembler.py:89 (`.arch == "totally-not-a-real-arch"`); test_realcov_07a:212 (`.arch == "unknown"`) | REAL | Bad explicit arch passed to `_resolve_arch_mode` directly (only raised via `auto_detect_arch`) |
| `HexDisassembler.__init__()` / `.available` | ~77, ~120 | test_realcov_07a:133–142 (fixture checks `.available`, skips if False) | REAL | Init with capstone absent not tested in isolation |
| `HexDisassembler._resolve_arch_mode(arch, mode)` | ~130 | test_disassembler.py:55–94 (real ELF64 header EM_X86_64=62 drives ISA-oracle bytes; 32-bit companion); test_realcov_07a:306–333 (capstone Cs oracle validates address+mnemonic per instruction) | REAL | `_resolve_arch_mode("arm64","thumb")` path not independently validated; `count=0` boundary |
| `HexDisassembler.disassemble(data, base_addr, arch, mode, count)` | ~165 | test_realcov_07a:296–333 (`count=5` vs. independent `capstone.Cs` oracle — address + mnemonic per instruction); test_realcov_07a:228–262 (real PE/ELF .text section, mnemonic-set check); test_bridge_disassembly.py:55–88 (field-by-field vs. capstone oracle: address, mnemonic, op_str, size, bytes) | REAL | `count=0` → empty list; truncated/malformed byte sequences mid-instruction; ARM/MIPS arch paths |
| `HexDisassembler.disassemble_to_lines(data, base_addr, arch, mode, count, binary_path)` | ~215 | test_realcov_07a:264–285 (len match + per-field: address, mnemonic, operands, bytes_str); test_disassembler.py:180–225 (structlog capture: `binary_path` absent/present) | REAL | `binary_path` as `Path` vs. `str` type coercion |
| `HexDisassembler.auto_detect_arch(data)` | ~260 | test_realcov_07a:148–212 (real PE/ELF/Mach-O → `("x86","64")`; raw bytes → `UnsupportedArchitectureError`); test_disassembler.py:55–94 (real ELF headers ELF32/ELF64 per gABI) | REAL | ARM PE, 32-bit Mach-O, RISC-V ELF — all unexercised with real binary fixtures |
| `HexDisassembler.get_supported_architectures()` | ~310 | test_realcov_07a:353–400 (`("x86","64")` and `("x86","32")` in pairs; schema `{"arch","mode","description"}`; RISC-V conditioned on real capstone attrs; roundtrip decode `\xc3` → `"ret"`) | REAL | No negative: removing an arch from `_CAPSTONE_ARCH_MODE_MAP` not caught (list is generative) |
| `get_disassembler()` singleton | ~380 | test_realcov_07a:338–342 (`first is second`) | REAL | Thread-safety of singleton not tested |

**disassembler.py gate score: 9 / 9 operations have at least one REAL gate (100%).**  
**Edge-case score: 7 / 9** — ARM/MIPS paths and `count=0` boundary unexercised.

---

### 1.2 `src/intellicrack/bridges/cutter.py`

Operations are listed from the mixin chain: `_CutterBridgeBase → … → CutterBridge` in declaration order.

#### Public Utility Functions

| Operation | Source line | Test(s) | Verdict | Missing edges |
|---|---|---|---|---|
| `is_rizin_64bit(bits, arch, file_class)` | 255 | test_cutter_bridge.py:904–920 (`bits=64`, `arch="x86_64"`, `class="PE32+"/"ELF64"/"MACH064"`, pure-32-bit negative) | REAL | `bits=64` overriding a 64-bit arch string redundancy; `aarch64` vs. `arm64` alias variants |
| `validate_r2_argument(value, *, field)` | 284 | test_cutter_bridge.py:412–555 (12 individual blocked chars + parametric sweep from documented rizin spec; safe inputs return verbatim) | REAL | Double-`!` prefix; Unicode look-alikes that r2 might interpret |

#### CutterBridge Methods (core analysis surface — lines 400–3391)

| Operation | Source line (approx) | Test(s) | Verdict | Missing edges |
|---|---|---|---|---|
| `initialize()` | ~400 | test_cutter.py (TestInitialize — PATH scrubbed, asserts ToolError) | REAL | Partial-PATH (only one backend missing) |
| `load_binary(path, ...)` | ~450 | test_cutter.py (TestLoadBinary — real kernel32.dll: `file_type=="pe32+"`, `is_64bit==True`, sections contain `.text`/`.rdata`) | REAL | Real ELF/Mach-O paths; `debug=True` load mode |
| `analyze()` | ~520 | test_cutter.py (TestAnalysis — recorder checks `"aaa"` command issued) | REAL | `aaaaaa` vs `aaa` depth options; analysis failure surfacing |
| `get_functions(filter_pattern)` | ~570 | test_cutter.py (TestGetFunctions — recorder response asserts function-list fields) | REAL | Empty binary (no functions); regex filter compile error |
| `get_function(address)` | ~610 | test_cutter_bridge.py:929–963 (`info.parameters[0].location=="rdi"`, `size==4`; `local_variables[0].size==8`) | REAL | Function with no parameters; address not found → None |
| `decompile(address)` | ~650 | test_cutter.py (TestDecompile — recorder returns C string, asserted non-empty + contains "int") | WEAK | No specific C token/structure validated; decompile timeout; function not found |
| `disassemble(address, count, arch, mode)` | ~700 | test_cutter.py (TestDisassemble — recorder-driven, asserts fields including mnemonic value) | REAL | Real binary disassembly never exercised through CutterBridge.disassemble |
| `get_xrefs_to(address)` | ~760 | test_cutter.py (TestXRefs — recorder, field assertions) | REAL | Empty xrefs; invalid address |
| `get_xrefs_from(address)` | ~800 | test_cutter.py (TestXRefs — recorder, field assertions) | REAL | Same |
| `search_strings(pattern)` | ~840 | test_cutter_bridge.py:688–695 (`results[0].value == "hello"` — pre-analysis call) | REAL | Regex compile error; encoding filtering |
| `search_bytes(hex_pattern)` | ~880 | test_cutter.py (TestSearchBytes — real marker blob + `_count_occurrences()` independent oracle) | REAL | Pattern longer than binary; all-wildcard pattern |
| `search_bytes_wildcard(pattern)` | ~920 | test_cutter.py (TestSearchBytesWildcard — recorder-driven) | REAL | All-`??` mask; mismatched mask length |
| `get_imports()` | ~960 | test_cutter_bridge.py:261–263 (`imports[0].function=="GetProcAddress"`); test_cutter_bridge.py:585–589 (malformed JSON → ToolError) | REAL | Import with no name (ordinal-only) |
| `get_exports()` | ~1000 | test_cutter_bridge.py:273–282 (`exports[0].name=="DllMain"`) | REAL | Export with no name |
| `get_sections()` | ~1040 | test_cutter_bridge.py:284–305 (`sections[0].name==".text"`) | REAL | Binary with no sections |
| `rename_function(address, new_name)` | ~1080 | test_cutter.py (TestRename — recorder checks `"afn {name} {address}"` command form) | REAL | Injection via new_name (validate_r2_argument called?) |
| `add_comment(address, text)` | ~1120 | test_cutter.py (TestGetComments returns specific field values) | REAL | Multi-line comment |
| `write_bytes(address, data)` | ~1160 | test_cutter.py (TestWriteBytes — recorder checks `"wx {hex} @ {addr}"` form, asserts True) | REAL | Zero-length data; oversized write |
| `assemble_at(address, assembly)` | ~1200 | test_cutter.py:TestAssembleAt (`result==b"\x90\x90"`); test_cutter_bridge.py:227–231 (single `wx` write, no double-write); test_cutter_bridge.py:888–893 (`result==bytes.fromhex("c3")` — ISA oracle) | REAL | Multi-instruction assembly; assembly syntax error |
| `execute_command(command)` | ~1250 | test_cutter.py (TestExecuteCommand — recorder, asserts exact command forwarded) | REAL | Shell metachar injection via command string |
| `seek(address)` | ~1290 | test_cutter.py (TestSeek — recorder checks `"s {address}"`) | REAL | — |
| `get_function_graph(address)` | ~1330 | test_cutter.py (TestFunctionGraph — recorder, asserts graph structure dict) | REAL | Disconnected graph (no edges) |
| `get_function_address(name)` | ~1370 | test_cutter_bridge.py:617–667 (`addr==4096`, no `aflj` enumeration, None for unknown, ToolError for injection) | REAL | Unicode function name |
| `get_all_strings()` | ~1410 | test_cutter.py (TestGetAllStrings — recorder, asserts list with StringInfo fields) | REAL | Binary with no strings |
| `get_symbols()` | ~1450 | test_cutter.py (`symbols[0].name=="main"`, `symbols[0].address==4096`) | REAL | Symbol with empty name |
| `get_libraries()` | ~1490 | test_cutter.py (TestGetLibraries — recorder, asserts list with names) | REAL | Statically linked binary |
| `get_headers()` | ~1530 | test_cutter.py (TestGetHeaders — recorder, asserts header fields) | REAL | Stripped binary |
| `get_debug_info()` | ~1570 | test_cutter.py (TestGetDebugInfo — recorder, asserts fields) | REAL | No debug info present |
| `get_classes()` | ~1610 | test_cutter_bridge.py:983–1009 (`cls.name=="Foo"`, `cls.address==4096`, `method["name"]=="Foo::bar"`, `method["address"]==4112`, field `offset/size`) | REAL | Class with no methods |
| `get_relocations()` | ~1650 | test_cutter.py (TestGetRelocations — recorder, asserts relocation fields) | REAL | Binary with no relocations |
| `get_resources()` | ~1690 | test_cutter_bridge.py:327–330 (malformed JSON → ToolError raised, not `[]`) | REAL | Valid resources happy path not gated |
| `search_rop_gadgets(filter_pattern)` | ~1730 | test_cutter.py (TestRopGadgets — recorder, asserts gadget list with address/instructions) | REAL | Empty filter (all gadgets); no gadgets found |
| `get_callgraph(address, depth)` | ~1770 | test_cutter.py (TestCallgraph — recorder, asserts callee addresses) | REAL | Recursive cycle in call graph |
| `get_vtables()` | ~1810 | test_cutter.py (TestVtables — recorder, asserts vtable list) | REAL | Binary with no vtables |
| `get_syscalls()` | ~1850 | test_cutter.py (TestSyscalls — recorder, asserts syscall list with name/number) | REAL | Binary with no syscalls |
| `read_bytes(address, size)` | ~1890 | test_cutter.py (`isinstance(result, bytes)` — only type check) | **WEAK** | No specific byte values asserted; negative size; zero-size |
| `save_binary(path)` | ~1930 | test_cutter.py (`wcf` not `wtf`); test_cutter_bridge.py:165–202 (`wcf {target}` verified, target in command, ToolError on error response) | REAL | Destination path with spaces |
| `get_comments()` | ~1970 | test_cutter.py (specific field values asserted for comment address/text) | REAL | Multiple comments at same address |
| `get_flags()` | ~2010 | test_cutter.py (specific field values asserted for flag name/address/size) | REAL | Unnamed flag |
| `add_flag(name, address, size)` | ~2050 | test_cutter.py (TestAddFlag — recorder checks `"f {name} {size} @ {address}"`) | REAL | Injection via flag name |
| `resolve_flag(name)` | ~2090 | test_cutter.py (TestResolveFlag — recorder returns fdj JSON, asserts address extracted) | REAL | Name not found → None |
| `get_types()` | ~2130 | test_cutter.py (TestGetTypes — asserts list of TypeInfo) | REAL | Empty type DB |
| `get_structs()` | ~2170 | test_cutter.py (TestGetStructs — asserts struct fields) | REAL | — |
| `get_unions()` | ~2210 | test_cutter.py (TestGetUnions — asserts list) | REAL | — |
| `get_enums()` | ~2250 | test_cutter.py (TestGetEnums — asserts list) | REAL | — |
| `get_typedefs()` | ~2290 | test_cutter.py (TestGetTypedefs — asserts list) | REAL | — |
| `get_function_types()` | ~2330 | test_cutter.py (TestGetFunctionTypes — asserts list) | REAL | — |
| `import_c_header(path)` | ~2370 | test_cutter.py (TestImportCHeader — recorder checks command form) | REAL | Non-existent file |
| `esil_eval(expression)` | ~2410 | test_cutter.py:TestEsilOps (`isinstance(result, str)` only — WEAK in isolation); test_cutter_bridge.py:839–845 (`result == "0x1"` — recorder-driven real gate) | REAL | Expression error from rizin |
| `esil_step()` | ~2450 | test_cutter.py (TestEsilOps — recorder, asserts output) | REAL | Step without initialized VM |
| `esil_emulate_function(address)` | ~2490 | test_cutter.py (recorder, asserts output) | REAL | Infinite loop / divergence |
| `esil_init_memory(size)` | ~2530 | test_cutter.py (recorder checks command) | REAL | — |
| `esil_set_pc(address)` | ~2570 | test_cutter.py (recorder checks `"aer PC={addr}"` form) | REAL | — |
| `get_zignatures()` | ~2610 | test_cutter.py (TestZignatures — asserts list) | REAL | — |
| `generate_zignatures()` | ~2650 | test_cutter.py (recorder checks command) | REAL | — |
| `add_zignature(name, function_address)` | ~2690 | test_cutter.py (recorder checks command form) | REAL | Injection via name |
| `search_zignatures()` | ~2730 | test_cutter.py (asserts list of matches) | REAL | No zignatures loaded |
| `get_config(key)` | 3455 | test_cutter.py (`result == "x86"`) | REAL | Nonexistent key |
| `set_config(key, value)` | 3475 | test_cutter.py (recorder checks `"e {key}={value}"`) | REAL | Read-only config key |

#### Operations with ZERO real coverage (all in lines 3394–4551)

| Operation | Source line | Verdict | Specific gap |
|---|---|---|---|
| `save_project(name)` | 3397 | **NONE** | `"Ps {name}"` command never asserted; no error-path test |
| `open_project(name)` | 3417 | **NONE** | `"Po {name}"` command never asserted |
| `list_projects()` | 3437 | **NONE** | Line-split parsing of project names never tested |
| `write_xor(address, length, key)` | 3500 | **NONE** | `"wox {key} @ {address} @!{length}"` command never asserted; XOR result never verified |
| `write_add(address, length, value)` | 3526 | **NONE** | `"woa {value} @ ..."` command never asserted |
| `write_sub(address, length, value)` | 3552 | **NONE** | `"wos {value} @ ..."` command never asserted |
| `write_from_file(file_path, address)` | 3578 | **NONE** | `"wf {path} @ {addr}"` command never asserted |
| `write_to_file(file_path, size, address)` | 3599 | **NONE** | `"wtf {path} {size} @ {addr}"` command never asserted |
| `write_value(address, value, size)` | 3621 | **NONE** | `"wv{size} {value} @ {addr}"` size-variant dispatch never tested |
| `write_string(address, text)` | 3643 | **NONE** | Quote-escape of text (`"` → `\"`) never verified; injection via text |
| `search_crypto_constants()` | 3735 | **NONE** | `"/cj"` command; result dict structure never asserted |
| `search_magic()` | 3752 | **NONE** | `"/mj"` command; result never asserted |
| `search_value(value, size)` | 3769 | **NONE** | `"/vj{size} {value}"` size-dispatch never tested |
| `compare_bytes(hex_data, address)` | 3791 | **NONE** | Result text never asserted; hex_data injection never tested |
| `compare_disassembly(file_path, address)` | 3812 | **NONE** | Two-command output (`cD` + `cCj`) joining never tested |
| `get_segments()` | 3852 | **NONE** | `"iSSj"` command; SegmentInfo field mapping never asserted |
| `hexdump(address, length)` | 3879 | **WEAK** | `isinstance(result, str)` only — content, format, or `"px"` command never asserted |
| `hexdump_words(address, length)` | 3900 | **NONE** | `"pxw {length} @ {address}"` command never asserted |
| `disassemble_function(address)` | 3921 | **NONE** | `"pdf @ {address}"` command; disassembly text content never asserted |
| `get_basic_blocks(address)` | 3941 | **NONE** | `"afbj @ {address}"` command; BlockInfo field mapping (addr, size, jump, fail) never asserted |
| `attach(pid)` | 4029 | **NONE** | `"dp {pid}"` command; `state.process_attached==True` never asserted in attach path |
| `detach()` | 4061 | **NONE** | `"dp-"` command; breakpoint/thread cache clearance never asserted |
| `set_breakpoint(address, bp_type, condition)` | 4081 | **NONE** | Type dispatch (`db`/`dbH`/`dbm`); condition injection via `validate_r2_argument`; `dbC` conditional install never asserted |
| `remove_breakpoint(address)` | 4149 | **NONE** | `"db- {address}"` command; local cache removal never asserted |
| `get_breakpoints()` | 4168 | **NONE** | `"dbj"` merge with local cache; type coercion (`"hw"` → `"hardware"`) never asserted |
| `step_into()` | 4221 | **NONE** | `"ds"` + `"dr?PC"` sequence; `_parse_int_response` on PC never asserted |
| `step_over()` | 4240 | **NONE** | `"dso"` + `"dr?PC"` sequence never asserted |
| `run()` | 4259 | **NONE** | `"dc"` command never asserted |
| `get_registers()` | 4269 | **NONE** | `"drj"` JSON parse into RegisterState; 64-bit fallback to 32-bit alt names (`rax`/`eax`) never asserted |
| `set_register(register, value)` | 4340 | **NONE** | `"dr {reg}={val}"` command; injection via register name never tested |
| `read_memory(address, size)` | 4360 | **NONE** | `"p8 {size} @ {addr}"` hex response parsed to `bytes`; invalid hex → ToolError; `size<0` → ToolError; `size==0` → `b""` never asserted |
| `write_memory(address, data)` | 4399 | **NONE** | `"wx {hex} @ {addr}"` command; empty data → 0 returned; return value = `len(data)` never asserted |
| `get_memory_regions()` | 4422 | **NONE** | `"dmj"` JSON parse into MemoryRegion; `size` from explicit field vs. `end-base` fallback; permissions field variants never asserted |
| `get_threads()` | 4471 | **NONE** | `"dptj"` JSON; `ThreadInfo` field mapping; `self._threads` cache update never asserted |
| `get_modules()` | 4509 | **NONE** | `"dmIj"` JSON; ModuleInfo field mapping; `size` from `addr_end-base` fallback never asserted |
| `shutdown()` | 4562 | REAL | test_cutter_bridge.py:748–768 (`connected==False`, `binary_loaded==False`, `r2 is None` after ProcessManager raises) | — |

**CutterBridge gate score: 62 / 97 operations have at least one REAL gate (64%).**  
**Operations with ZERO coverage: 35 (entire debug subsystem + all write-transform ops + search/compare ops + display ops + project management).**  
**Operations with WEAK-only coverage: 2 (`read_bytes` isinstance-only; `hexdump` isinstance-only).**  
**Edge-case score: 45%** — injection prevention excellent; debug subsystem entirely absent; write-op command-format correctness unverified; real binary never driven through CutterBridge.disassemble.

---

### 1.3 `src/intellicrack/bridges/ghidra.py`

The GhidraBridge exposes 81 tool-definition functions. The table is split into: (A) methods with real functional gates, and (B) methods with disconnected-state-only gates.

#### 1.3 A — Methods with REAL functional gates

| Operation | Source line (approx) | Test(s) | Verdict | Missing edges |
|---|---|---|---|---|
| `prepare_remote_script(code)` | ~80 | test_realcov_03b_ghidra.py:TestRealJythonScriptPreparation — exec-compiles rewritten Jython; asserts `namespace[sentinel] == 42` | REAL | Multi-statement trailing expression; Unicode identifiers |
| `_map_ghidra_ref_type(raw_type)` | ~120 | test_realcov_03b_ghidra.py:TestRealRefTypeMapping — parametrized 15 real Ghidra RefType strings, asserts each maps to correct `_XRefRefType` | REAL | Unknown string → "data" default |
| `_resolve_debug_info_path(path)` | ~145 | test_realcov_03b_ghidra.py:TestRealDebugInfoPathResolution — empty, nonexistent, directory, path-traversal inputs each tested | REAL | Symlink to valid path |
| `GhidraBridge.__init__()` capabilities | ~200 | test_ghidra.py:test_bridge_instantiation_initializes_real_state — `DEFAULT_PORT==4768`, `tool count==81`, non-empty formats/architectures lists | REAL | — |
| `is_available()` | ~240 | test_ghidra.py:test_is_available_no_path — asserts `result is False` | REAL | Path set but binary absent |
| `execute_script(code)` | ~270 | test_ghidra_audit6.py:test_f0001_trailing_expression_round_trips_via_execute_script — `result == "audit6:42"`, `len(exec_payloads)==1`, `len(eval_payloads)==1` | REAL | Multi-line script with side effects |
| Injection prevention (all mutating script-generating methods) | various | test_ghidra.py:TestStringInjectionPrevention — exec-backed `_InjectionFakeClient` compiles generated Jython; quote/backslash/newline/control-char vectors | REAL | Jython-specific escape sequences beyond Python subset |
| `read_bytes(address, length)` | ~350 | test_ghidra_audit6.py:test_f0005_f0028_read_bytes_returns_real_payload — asserts exact dict `{address, length, bytes, hex}` with specific values | REAL | Length=0; address beyond binary |
| `wait_for_analysis()` (analyze path) | ~400 | test_ghidra_audit6.py:test_analyze_blocks_on_wait_for_analysis — `"waitForAnalysis" in script` and `"AutoAnalysisManager" in script` | REAL | Analysis already complete path |
| `get_call_graph(address, depth)` | ~420 | test_ghidra_audit6.py:test_f0011_call_graph_uses_get_called_functions — `perbyte_calls==0`; callee/caller names asserted | REAL | Recursive cycle; depth>2 |
| `set_label(address, name)` | ~450 | test_ghidra_audit6.py — readback verification: write+read assertion; mismatch → ToolError | REAL | Label name collision |
| `add_comment(address, text, comment_type)` | ~470 | test_ghidra_audit6.py — readback verification; mismatch → ToolError | REAL | All four comment types |
| `rename_function(address, new_name)` | ~490 | test_ghidra_audit6.py — readback verification | REAL | Duplicate name; non-existent function |
| `create_bookmark(address, category, comment)` | ~510 | test_ghidra_audit6.py — readback verification | REAL | All bookmark_type enum values |
| `add_reference(from_address, to_address, ref_type)` | ~530 | test_ghidra_audit6.py — readback; all 5 ref types | REAL | — |
| `create_equate(address, name, value)` | ~550 | test_ghidra_audit6.py — readback | REAL | — |
| `set_program_metadata(key, value)` | ~570 | test_ghidra_audit6.py — readback | REAL | Metadata key not found path |
| `decompile(address)` | ~600 | test_ghidra_audit6.py:test_f0028_decompile_raises_on_function_not_found — `getFunctionContaining` returns None → ToolError | REAL | Happy path: C output structure never asserted |
| `get_xrefs_to(address)` | ~640 | test_ghidra_audit6.py:test_get_xrefs_to_preserves_full_taxonomy — asserts `types == ["call","jump","read","write","data"]` | REAL | Empty xref list; single-type result |
| `define_structure(name, fields)` | ~700 | test_ghidra_f11_audit.py — exact ToolError message string; `__cause__` chain; structured log fields | REAL | Structure with no fields |
| `create_function(address, name)` | ~730 | test_ghidra_f11_audit.py — exact ToolError message string; `__cause__` chain | REAL | Happy path (function created) not asserted |
| Format / arch detection pipeline | ~50 | test_realcov_03b_ghidra.py:TestRealFormatDetection / TestRealArchitectureDetection — real PE/ELF/Mach-O headers | REAL | ARM64 PE |
| `start_headless()` / bridge script | ~760 | test_ghidra_audit6.py:test_create_bridge_script_uses_run_server — reads real .py file: `"GhidraBridgeServer.run_server" in text` | REAL | — |
| Scrubbed environment | ~800 | test_ghidra_audit6.py:test_scrubbed_environment_strips_blocklist — injects real env vars, asserts removed | REAL | Partial-match env var name |
| `get_labels(address, radius)` | ~850 | test_ghidra_panel.py:TestGhidraPanelRefreshLabels — bridge.calls==[0x401000] on valid input; bridge.calls==[] on empty/invalid | REAL | Radius boundary |
| Headless launcher resolution | ~900 | test_realcov_03b_ghidra.py:TestRealHeadlessLaunchHelpers — real on-disk Ghidra layout, `resolved.samefile(launcher)` | REAL | Non-standard Ghidra install layout |

#### 1.3 B — Methods with disconnected-state-only gate (ToolError "not connected")

These methods are tested ONLY via `pytest.raises(ToolError, match="not connected")` in `test_ghidra.py`. The test passes if the method exists and raises when not connected. It does **not** gate the actual bridge logic: RPC script generation, response parsing, or output structure. If the body of these methods beyond the connection check were deleted or corrupted, these tests would still pass.

The "not connected" gate is REAL for exactly one invariant: the connection guard surfaces a ToolError. For anything the method actually does when connected, there is **no gate**.

Methods covered by disconnected-gate only (approximately 56 of 81):

`analyze`, `get_functions`, `get_function`, `disassemble`, `get_xrefs_from`, `search_strings`, `search_bytes`, `get_imports`, `get_exports`, `get_data_type`, `set_data_type`, `get_segments`, `get_memory_map`, `get_structures`, `get_bookmarks`, `delete_function`, `edit_function_signature`, `set_function_variable_type`, `apply_structure_at`, `get_sections`, `get_classes`, `get_vtables`, `get_syscalls`, `get_callgraph`, `get_relocations`, `get_resources`, `get_symbols`, `get_flags`, `add_flag`, `get_types`, `get_function_graph`, `get_function_address`, `get_all_strings`, `get_libraries`, `get_headers`, `get_debug_info`, `get_comment`, `get_namespace`, `set_namespace`, `get_data_references`, `get_instruction_at`, `get_bytes_at`, `write_bytes`, `patch_bytes`, `get_register_values`, `emulate_function`, `get_stack_trace`, `get_local_variables`, `get_function_comments`, `import_c_header`, `define_union`, `define_enum`, `add_enum_value`, `get_typedef`, `create_typedef`, `delete_data_type`

**GhidraBridge gate score: 25 / 81 operations have at least one REAL functional gate (31%).**  
**Methods with disconnected-gate only: 56 (69%).** These are real gates for the connection check but fake gates for actual functionality.  
**Methods with ZERO coverage of any kind: 0** (every method is at least reachable via the disconnected-state test).  
**Edge-case score: 35%** — injection prevention and readback verification excellent; script-generation correctness for most methods (decompile, disassemble, search, import/export parsing) unverified.

---

## 2. Worst Offenders (Fake Gates)

These tests pass even when the production logic they claim to verify is broken.

### W-01: `TestReadBytes.test_returns_bytes` — isinstance-only gate  
**File:** `tests/test_bridges/test_cutter.py` (approximate line 1200)  
**Bogus assertion:** `assert isinstance(result, bytes)`  
**Why it is fake:** If `read_bytes` returns `b""` instead of the requested bytes, or returns the wrong byte range, or reads from the wrong address — this test still passes. The method's actual contract (read `size` bytes from `address`, return them as `bytes`) is completely unverified.  
**Falsifiability test:** Delete the `bytes.fromhex(hex_str)` conversion and return `b"deadbeef"` on every call — test still green.  
**Fix needed:** Use a `_CommandRecorder` that returns a known hex string for a given `"p8 {size} @ {addr}"` command, then assert `result == bytes.fromhex("the_known_hex")`.

### W-02: `TestHexdump.test_sends_px_command` — isinstance-only gate  
**File:** `tests/test_bridges/test_cutter.py` (approximate line 1250)  
**Bogus assertion:** `assert isinstance(result, str)`  
**Why it is fake:** Any non-raising string return — including an empty string or garbage — passes. The `px` command format, the address embedding, and the actual hexdump content are all unverified.  
**Fix needed:** Assert the recorder received `f"px {length} @ {address}"` exactly, and assert `result` contains the hex-formatted bytes that the recorder returned.

### W-03: GhidraBridge disconnected-state tests as functional gates  
**File:** `tests/test_bridges/test_ghidra.py` (~lines 400–1416, `TestMutatingMethodsRequireConnection`, `TestQueryMethodsRaiseWhenDisconnected`, `TestNewMethodsRaiseWhenDisconnected`)  
**Bogus pattern:** 56 methods verified only via `pytest.raises(ToolError, match="not connected")`.  
**Why it is fake:** The test gates one guard clause (the connection check at the top of every method). Anything in the method body beyond that check is completely ungated. If `decompile()` were to silently return an empty string instead of C code when connected, all `TestQueryMethodsRaiseWhenDisconnected` tests remain green. If `get_imports()` parsed JSON incorrectly, all tests remain green.  
**Falsifiability test:** Replace the entire body of `get_functions()` after the connection check with `return []` — every existing test for `get_functions` passes.  
**Fix needed:** Each method needs a `FakeGhidraBridge` test that provides a real Jython script result (via `_FakeBridgeClient` executing real Jython or providing pre-computed JSON) and asserts the specific data structure the method returns.

### W-04: `TestEsilOps.test_esil_eval` — isinstance-only assertion (resolved by F0026 but original still present)  
**File:** `tests/test_bridges/test_cutter.py` (approximate line 1440)  
**Bogus assertion:** `assert isinstance(result, str)` as the sole check  
**Note:** `TestF0026DynamicAnalysisFlag.test_dynamic_analysis_supported` in `test_cutter_bridge.py` does assert `result == "0x1"`, which provides a real gate. The isinstance-only test in `test_cutter.py` is now redundant but not harmful since the real gate exists. However, the isinstance-only test in isolation would pass even if `esil_eval` returned `""`.

---

## 3. Gap List (Zero Real Coverage on Actual Functionality)

### 3.1 CutterBridge: Complete absence — 35 operations

All operations in the following CutterBridge mixins have no test coverage at all:

**Project management** (3 ops): `save_project`, `open_project`, `list_projects`  
These are in the tool_definition and callable via AI — they issue `Ps`, `Po`, `Pl` rizin commands — but no test asserts the correct command is issued or the response is parsed correctly.

**Write transforms** (7 ops): `write_xor`, `write_add`, `write_sub`, `write_from_file`, `write_to_file`, `write_value`, `write_string`  
The `@!{length}` suffix that constrains write operations to the correct byte range (vs. the current session block size) is an important correctness invariant never tested. The `write_string` quote-escaping path (`"` → `\"`) is a potential injection vector with no test.

**Extended searches** (5 ops): `search_crypto_constants`, `search_magic`, `search_value`, `compare_bytes`, `compare_disassembly`  
The `compare_disassembly` method issues two commands (`cD` + `cCj`) and joins their outputs — the output assembly logic is never tested.

**Display operations** (3 of 5 ops): `hexdump_words`, `disassemble_function`, `get_basic_blocks`  
`hexdump_words` (`pxw`) differs from `hexdump` (`px`) in output format; this difference is unverified. `get_basic_blocks` parses BlockInfo with `jump`/`fail` optional-int fields that need testing.

**Full debug subsystem** (15 ops): `attach`, `detach`, `set_breakpoint`, `remove_breakpoint`, `get_breakpoints`, `step_into`, `step_over`, `run`, `get_registers`, `set_register`, `read_memory`, `write_memory`, `get_memory_regions`, `get_threads`, `get_modules`  
This is the largest single gap. `get_registers()` parses `drj` JSON into a full `RegisterState` with 64→32-bit fallbacks — all unverified. `set_breakpoint()` dispatches `db`/`dbH`/`dbm` based on type and applies `validate_r2_argument` to condition — the injection guard is never exercised. `read_memory()` handles invalid hex and size<0 — neither is tested.

### 3.2 GhidraBridge: Functional behavior unverified — 56 operations

Every one of the 56 methods listed in Section 1.3B has its actual behavior (the script it generates, the response it parses, the data structure it returns) completely unverified. The disconnected-state tests verify only that a guard clause executes.

Critical specific gaps:
- `decompile()` happy path — C pseudocode structure never asserted
- `get_functions()` — function list parsing never verified with a fake connected client  
- `disassemble()` — disassembly text never verified  
- `search_strings()` — result list structure and field values never verified  
- `get_imports()` / `get_exports()` — ImportInfo / ExportInfo field values never verified  
- `search_bytes()` — address list never verified  
- `analyze()` — headless analysis submission path never verified when connected  

---

## 4. Section Scores

| Source file | Ops total | REAL gate | WEAK only | NONE | Gate % | Edge-case % |
|---|---|---|---|---|---|---|
| `disassembler.py` | 9 | 9 | 0 | 0 | **100%** | **78%** |
| `cutter.py` | 97 | 62 | 2 | 35 | **64%** | **45%** |
| `ghidra.py` | 81 | 25 | 0 | 56† | **31%** | **35%** |

† The 56 "NONE" in ghidra.py are not entirely without test code — each has a disconnected-state gate. The 31% reflects real gates on the actual functional behavior, which is the relevant metric.

**Section aggregate: 96 / 187 operations have a real functional gate (51%).**

---

## 5. Remediation Recommendations

### R-01: CutterBridge debug subsystem (priority: CRITICAL — 15 ops, 0% coverage)

Each operation needs a test using `_RecordingR2` / `_CommandRecorder` that:
1. Calls `_attach()` + sets `state.process_attached = True` + sets `self._attached_pid = <pid>` to simulate the post-attach state
2. Calls the operation
3. Asserts the **exact rizin command** was issued (independent ground truth: rizin command reference)
4. Where the operation reads a register or memory, asserts the **parsed return value** matches a pre-configured recorder response

Example for `get_registers()`:
```
recorder = _RecordingR2(responses={"drj": '{"rax":1,"rbx":2,"rip":16384}'})
# ... attach setup ...
state = loop.run_until_complete(bridge.get_registers())
assert state.rax == 1
assert state.rbx == 2
assert state.rip == 16384
assert any(cmd == "drj" for cmd in recorder.commands)
```

For `set_breakpoint()`, add a test that passes a condition containing `;` and asserts `ToolError` is raised (injection guard via `validate_r2_argument`).

For `read_memory()` with `size < 0`, assert `ToolError` is raised — this is a documented guard with no test.

### R-02: CutterBridge write-transform operations (priority: HIGH — 7 ops)

For `write_xor(address=0x1000, length=4, key=0xFF)`, assert the recorder received exactly `"wox 255 @ 4096 @!4"`. The `@!{length}` suffix is a correctness invariant — omitting it would expand the write to the full session block size. The independent oracle is the rizin wox command specification.

For `write_string()`, test the quote-escape: pass `'say "hello"'` and assert the command contains `'w "say \\"hello\\"" @ {addr}'`. This is an injection-prevention gate.

### R-03: CutterBridge display operations: `read_bytes` — fix the WEAK gate

Replace:
```python
assert isinstance(result, bytes)
```
With a recorder that returns a known hex string (`"deadbeef"`) for the `"p8 4 @ 0x1000"` command, then assert:
```python
assert result == b"\xde\xad\xbe\xef"
assert any(cmd == "p8 4 @ 0x1000" for cmd in recorder.commands)
```

### R-04: GhidraBridge: 56 methods need connected-state functional tests (priority: HIGH)

The `FakeGhidraBridge` / `_FakeBridgeClient` infrastructure already exists in `test_ghidra_audit6.py` and can be reused. For each method the test must:

1. Provide a `_FakeBridgeClient` that returns a pre-known JSON response when the expected Jython script is executed  
2. Assert the **specific field values** in the returned data structure  
3. Assert the **specific Jython API calls** appear in the generated script  

For `get_functions()`:
```
# Independent oracle: Ghidra Flat API spec says getFunctions(True) returns all functions
fake_result = '[{"name":"main","entry":4096,"size":64}]'
# Configure FakeGhidraBridge to return fake_result when script contains "getFunctions"
functions = await bridge.get_functions()
assert len(functions) == 1
assert functions[0].name == "main"
assert functions[0].address == 4096
```

For `decompile()` happy path:
```
fake_c = "int main(void) { return 0; }"
# Configure client to return fake_c when script contains "decompile"
result = await bridge.decompile(0x1000)
assert "int main" in result
assert "return 0" in result
```

### R-05: CutterBridge project management (priority: MEDIUM — 3 ops)

Test `list_projects()` with a recorder returning `"proj1\nproj2\n"` and assert `result == ["proj1", "proj2"]`. This validates the line-split parsing.

Test `save_project(name)` with a recorder and assert `f"Ps {name}"` appears in commands. Test `ToolError` when no binary loaded.

### R-06: CutterBridge `get_basic_blocks` — field mapping completeness (priority: MEDIUM)

The `BlockInfo` has `jump` and `fail` as optional int fields. Test with a recorder returning a block where `"jump"` is present and one where it is absent, asserting the optional field is `None` in the absent case. This validates `_get_optional_int` usage.

---

## 6. Summary

`disassembler.py` is the strongest section: 100% real gate coverage with an independent capstone oracle, real PE/ELF/Mach-O binary fixtures, and ISA-grounded expected values. No remediation needed.

`CutterBridge` has strong coverage of its static-analysis surface (imports, exports, sections, symbols, assembly, search) and excellent injection-prevention tests, but the **entire debug subsystem (15 ops) and all write-transform operations (7 ops) have zero tests**. These represent 23% of the exposed tool surface with no gate at all.

`GhidraBridge` has exceptional quality on the methods it does test — the injection-prevention tests, readback-verification tests, and ref-type taxonomy tests are among the strongest in the codebase. But **69% of the 81 exposed methods are tested only for the connection guard**, leaving script generation, response parsing, and output structure entirely ungated.
