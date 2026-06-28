# Group 02 Verification Report

**Auditor:** test-reviewer (GROUP 02, adversarial)
**Date:** 2026-06-27
**Protocol:** `audit/verification/PROTOCOL.md`
**Assigned sources:**
- `audit/test-coverage-audit/section-02-disassembler-bridges.md` (full — Ghidra + Cutter + disassembler inventory tables)
- `audit/test-coverage-audit/section-15-ui-panels.md` (full — Verdict per-test-file rows)

**Note:** `disassembler.py` (9/9 REAL gates, 100%) is out of scope — all rows already marked REAL in the audit. Only non-REAL findings are enumerated below.

---

## Findings Table

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation) |
|---|---|---|---|---|
| **CutterBridge — 37 findings** |||||
| 1 | `decompile(address)` (cutter.py:~650) | WEAK | NOT_RESOLVED | Only `test_decompile_no_binary` (error path) at test_cutter.py:1187 remains; TestDecompile class removed. No gate for happy path: C-code structure, `pdg` command framing, or decompiled token content. Missing: assert `result` contains a known C token against recorder response. |
| 2 | `read_bytes(address, size)` (cutter.py:~1890) | WEAK | RESOLVED | test_cutter.py:1490 `assert result == b"\x48\x8b\x05"` + :1491 `assert f"p8 3 @ {0x1000}" in rec.commands` · oracle: `bytes.fromhex("48 8b 05")` computed independently · mutation: swap `p8` to `p8j` in bridge → command assertion fails |
| 3 | `hexdump(address, length)` (cutter.py:3879) | WEAK | RESOLVED | test_cutter.py:1580 `assert result == "- offset -   0 1  2 3\n0x00001000  9090 9090"` + :1581 `assert f"px 128 @ {0x1000}" in rec.commands` · oracle: pre-loaded recorder string · mutation: emit `pxw` instead of `px` → command assertion fails |
| 4 | `save_project(name)` (cutter.py:3397) | NONE | RESOLVED | test_cutter_wave2a_project.py:95 `assert f"Ps {name}" in rec.commands` · oracle: rizin `Ps` command spec · mutation: emit `Po {name}` instead → assertion fails |
| 5 | `open_project(name)` (cutter.py:3417) | NONE | RESOLVED | test_cutter_wave2a_project.py:120 `assert f"Po {name}" in rec.commands` · oracle: rizin `Po` command spec · mutation: drop `name` from command → assertion fails |
| 6 | `list_projects()` (cutter.py:3437) | NONE | RESOLVED | test_cutter_wave2a_project.py:145 `assert result == ["proj1", "proj2"]` against `"proj1\nproj2\n"` response · oracle: newline-split of recorder response · mutation: skip line-split → result is one string, assertion fails |
| 7 | `write_xor(address, length, key)` (cutter.py:3500) | NONE | RESOLVED | test_cutter_wave2a_project.py:188 `assert f"wox 255 @ {_ADDR} @!4" in rec.commands` · oracle: rizin `wox key @ addr @!len` spec · mutation: drop `@!{length}` suffix → assertion fails (correctness invariant: without `@!` write expands to session block size) |
| 8 | `write_add(address, length, value)` (cutter.py:3526) | NONE | RESOLVED | test_cutter_wave2a_project.py:218 `assert f"woa {value} @ {_ADDR} @!{length}" in rec.commands` · oracle: rizin `woa` spec · mutation: drop `@!` suffix → assertion fails |
| 9 | `write_sub(address, length, value)` (cutter.py:3552) | NONE | RESOLVED | test_cutter_wave2a_project.py:243 `assert f"wos {value} @ {_ADDR} @!{length}" in rec.commands` · oracle: rizin `wos` spec · mutation: drop `@!` suffix → assertion fails |
| 10 | `write_from_file(file_path, address)` (cutter.py:3578) | NONE | RESOLVED | test_cutter_wave2a_project.py:268 `assert f"wf {path} @ {_ADDR}" in rec.commands` · oracle: rizin `wf` spec · mutation: omit `@ {addr}` → assertion fails |
| 11 | `write_to_file(file_path, size, address)` (cutter.py:3599) | NONE | RESOLVED | test_cutter_wave2a_project.py:293 `assert f"wtf {path} {size} @ {_ADDR}" in rec.commands` · oracle: rizin `wtf` spec · mutation: swap argument order → assertion fails |
| 12 | `write_value(address, value, size)` (cutter.py:3621) | NONE | RESOLVED | test_cutter_wave2a_project.py:319–361 (4 tests, wv1/wv2/wv4/wv8 dispatch) · oracle: rizin `wv{n}` command spec · mutation: ignore `size` arg, always emit `wv4` → wv1/wv2/wv8 assertions fail |
| 13 | `write_string(address, text)` (cutter.py:3643) | NONE | RESOLVED | test_cutter_wave2a_project.py:400 `assert expected in rec.commands` where expected `'w "say \\"hi\\"" @ {_ADDR}'` · oracle: rizin `w` command + Python `str.replace('"', '\\"')` · mutation: omit quote escape → assertion fails (injection-prevention gate) |
| 14 | `search_crypto_constants()` (cutter.py:3735) | NONE | NOT_RESOLVED | No test found in any test file. `/cj` command never asserted; result dict structure unverified. Missing: recorder returning `[{"offset":4096,"name":"AES_SBOX"}]` → assert `result[0].offset == 4096`. |
| 15 | `search_magic()` (cutter.py:3752) | NONE | NOT_RESOLVED | No test found. `/mj` command never asserted. Missing: recorder returning magic-match JSON → assert parsed fields. |
| 16 | `search_value(value, size)` (cutter.py:3769) | NONE | NOT_RESOLVED | No test found. `/vj{size} {value}` size-dispatch never verified. Missing: assert `f"/vj4 {value}" in rec.commands`. |
| 17 | `compare_bytes(hex_data, address)` (cutter.py:3791) | NONE | NOT_RESOLVED | No test found. Result text never asserted. Missing: recorder returning comparison text → assert `result` matches known output. |
| 18 | `compare_disassembly(file_path, address)` (cutter.py:3812) | NONE | NOT_RESOLVED | No test found. Two-command output (`cD` + `cCj`) join logic never verified. Missing: assert both commands issued in order; assert joined result. |
| 19 | `get_segments()` (cutter.py:3852) | NONE | NOT_RESOLVED | No test found. `iSSj` command; `SegmentInfo` field mapping never asserted. Missing: recorder returning segment JSON → assert `result[0].name == ".text"`. |
| 20 | `hexdump_words(address, length)` (cutter.py:3900) | NONE | NOT_RESOLVED | No test found. `pxw` command (different from `px`) never asserted. Missing: assert `f"pxw {length} @ {address}" in rec.commands` and verify `result` string format. |
| 21 | `disassemble_function(address)` (cutter.py:3921) | NONE | NOT_RESOLVED | No test found. `pdf @ {address}` command; disassembly text content never asserted. Missing: recorder returning disassembly text → assert `"push rbp" in result`. |
| 22 | `get_basic_blocks(address)` (cutter.py:3941) | NONE | RESOLVED | test_cutter.py:1597 `assert blocks[0].address == 4096`, :1598 `assert blocks[0].size == 20`, :1599 `assert blocks[0].jump == 4116` · oracle: JSON `{"addr":4096,"size":20,"jump":4116,"fail":null}` from recorder · mutation: misparse `jump` as `fail` field → `jump == 4116` fails |
| 23 | `attach(pid)` (cutter.py:4029) | NONE | RESOLVED | test_cutter_wave2a_debug.py:178 `assert "dp 1337" in recorder.commands` + :190 `assert state.process_attached is True` · oracle: rizin `dp {pid}` spec · mutation: emit `dp- 1337` instead → command assertion fails |
| 24 | `detach()` (cutter.py:4061) | NONE | RESOLVED | test_cutter_wave2a_debug.py:240 `assert "dp-" in recorder.commands` + :251 `assert state.process_attached is False` · oracle: rizin `dp-` spec · mutation: emit `dp` instead of `dp-` → assertion fails |
| 25 | `set_breakpoint(address, bp_type, condition)` (cutter.py:4081) | NONE | RESOLVED | test_cutter_wave2a_debug.py:305 (`db` cmd), :344 (`dbH` hardware), :371 (`dbm` memory), :398 (`dbC` conditional) + :439 injection guard (`;` in condition → ToolError) · oracle: rizin breakpoint command spec · mutation: emit `db` for hardware type → `dbH` assertion fails |
| 26 | `remove_breakpoint(address)` (cutter.py:4149) | NONE | RESOLVED | test_cutter_wave2a_debug.py:465 `assert f"db- {_ADDR}" in recorder.commands` + :478 `assert _ADDR not in bridge._breakpoints` · oracle: rizin `db-` spec · mutation: use `db {addr}` instead of `db- {addr}` → assertion fails |
| 27 | `get_breakpoints()` (cutter.py:4168) | NONE | RESOLVED | test_cutter_wave2a_debug.py:506 `dbj` command + :532 local cache merge + :532 `"hw"` → `"hardware"` type coercion → asserted `type == "hardware"` · oracle: recorder-provided JSON + coercion spec · mutation: omit type coercion → `type == "hw"` not `"hardware"` → assertion fails |
| 28 | `step_into()` (cutter.py:4221) | NONE | RESOLVED | test_cutter_wave2a_debug.py:594 `"ds" in recorder.commands` + :605 PC read via `dr?PC` + :629 `assert result == expected_pc` · oracle: integer-parsed PC from recorder response · mutation: use `dso` instead of `ds` → assertion fails |
| 29 | `step_over()` (cutter.py:4240) | NONE | RESOLVED | test_cutter_wave2a_debug.py:644 `"dso" in recorder.commands` + :655 `assert result == expected_pc` · oracle: parsed PC int · mutation: use `ds` instead of `dso` → assertion fails |
| 30 | `run()` (cutter.py:4259) | NONE | RESOLVED | test_cutter_wave2a_debug.py:670 `assert "dc" in recorder.commands` · oracle: rizin `dc` (continue) spec · mutation: emit `ds` instead → assertion fails |
| 31 | `get_registers()` (cutter.py:4269) | NONE | RESOLVED | test_cutter_wave2a_debug.py:735 `assert state.rax == 1` + :753 32-bit `eax` → `rax` fallback asserted · oracle: recorder JSON `{"rax":1,"rbx":2,"rip":16384}` · mutation: drop 32→64-bit fallback path → `state.rax` stays `None` when only `eax` key present → assertion fails |
| 32 | `set_register(register, value)` (cutter.py:4340) | NONE | RESOLVED | test_cutter_wave2a_debug.py:799 `assert f"dr {reg}={val}" in recorder.commands` + :822 injection guard (`;` → ToolError) · oracle: rizin `dr` spec · mutation: emit `dr {val}={reg}` (swapped) → assertion fails |
| 33 | `read_memory(address, size)` (cutter.py:4360) | NONE | RESOLVED | test_cutter_wave2a_debug.py:837 `assert result == bytes.fromhex("deadbeef")` + :850 `size==0` → `b""` no-command + :862 `size<0` → ToolError + :873 invalid hex → ToolError · oracle: `bytes.fromhex` · mutation: return raw hex string instead of bytes → equality assertion fails |
| 34 | `write_memory(address, data)` (cutter.py:4399) | NONE | RESOLVED | test_cutter_wave2a_debug.py:888 `assert f"wx deadbeef @ {_ADDR}" in recorder.commands` + :902 empty data returns 0 · oracle: hex encoding of `b"\xde\xad\xbe\xef"` · mutation: omit `@ {addr}` → assertion fails |
| 35 | `get_memory_regions()` (cutter.py:4422) | NONE | RESOLVED | test_cutter_wave2a_debug.py:929 explicit `size` field used, :958 `end-base` fallback asserted, :981 permissions field variants · oracle: recorder JSON; subtraction `end-base` is independent · mutation: always use explicit size, ignore fallback → size==0 instead of computed value → assertion fails |
| 36 | `get_threads()` (cutter.py:4471) | NONE | RESOLVED | test_cutter_wave2a_debug.py:1016 `assert thread.tid == expected_pid` + :1043 `_threads` cache updated · oracle: recorder `dptj` JSON with `pid` key · mutation: map `pid` → `ppid` field → `tid` mismatch → assertion fails |
| 37 | `get_modules()` (cutter.py:4509) | NONE | RESOLVED | test_cutter_wave2a_debug.py:1068 `"dmIj" in recorder.commands` + :1079 name derived from `file_path` when `name` absent · oracle: `os.path.basename(path)` · mutation: use `dmj` instead of `dmIj` → command assertion fails |
| **GhidraBridge — 56 findings (disconnected-state-only list)** |||||
| 38 | `analyze` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | Wave-2a files do not cover `analyze` in connected-state. No test asserts script contains `"AutoAnalysisManager"` when bridge is connected. Missing: `_FakeGhidraBridge` with `remote_eval` returning analysis status → assert `"analyzeAll" in script`. |
| 39 | `get_functions(filter_pattern)` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_analysis.py:185 field-by-field: `name`, `address`, `size`, `calling_convention`, `return_type` + :221 `getFunctionManager` in script + :245 filter excludes non-matching · oracle: `_FakeGhidraBridge.eval_response` pre-loaded JSON · mutation: drop `size` field from result parsing → `func.size` missing → assertion fails |
| 40 | `get_function(address)` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_analysis.py:291 `parameters` + `variables` fields asserted + :328 `getFunctionContaining(toAddr(...))` in script + :270 `None` when not found · oracle: pre-loaded eval_response dict · mutation: use `getFunctionAt` instead of `getFunctionContaining` → script assertion fails |
| 41 | `disassemble(address, count)` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_analysis.py:352 per-instruction `address`/`mnemonic`/`bytes_str`/`operands` + :382 `getListing` + `getInstructionAt` in script · oracle: eval_response instruction list · mutation: drop `bytes_str` field → assertion on `bytes_str` fails |
| 42 | `get_xrefs_from(address)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | Wave-2a files (xrefs.py file covers `delete_reference`, `create_namespace`, `get_namespaces`, `search_symbols`, `get_calling_conventions`, `get_relocations`, `get_memory_map`, `get_segments`) but not `get_xrefs_from`. No functional gate for XRef generation script or parsed `XRefInfo` struct. Missing: `_FakeGhidraBridge` with reference list → assert `result[0].from_address`. |
| 43 | `search_strings(pattern)` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_edits.py:532 `StringInfo` field assertions (`address`, `value`, `encoding`, `length`) + `getListing` in script · oracle: eval_response string list · mutation: omit `encoding` field parsing → field assertion fails |
| 44 | `search_bytes(hex_pattern)` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_edits.py:568 address list parsed via `int()` conversion + `findBytes` in script · oracle: eval_response address list → independent `int()` · mutation: return raw strings instead of int addresses → type/value assertion fails |
| 45 | `get_imports()` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_analysis.py:406 `dll`/`function`/`address` fields per import + :436 `getExternalSymbols` in script · oracle: eval_response import list · mutation: swap `dll` and `function` fields → field name assertion fails |
| 46 | `get_exports()` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_analysis.py:458 ordinal via `enumerate` index + address + :489 `isExternalEntryPoint` in script · oracle: eval_response export list · mutation: hardcode ordinal to 0 → ordinal assertion fails |
| 47 | `get_data_type(address)` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_datatypes.py:127 `name` + `size` from script result + :201 `getDataAt` API in script · oracle: eval_response dict · mutation: use `getDataBefore` instead of `getDataAt` → script assertion fails |
| 48 | `set_data_type(address, type_name)` (ghidra.py) | DISCONN-ONLY | RED_BY_DESIGN | test_ghidra_wave2a_datatypes.py:223 — PD-003: `prepare_remote_script` if/else block never captures result; gate asserts `{"success": True}` but production code returns nothing → test is RED · PD-003 |
| 49 | `get_segments()` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_xrefs.py:495 12-field assertion including `type`, `source_name`, `comment` + `getSourceName`/`getType` API calls in script · oracle: eval_response segment list · mutation: omit `source_name` field → assertion fails |
| 50 | `get_memory_map()` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_xrefs.py:426 all 9 block fields (`name`, `start`, `end`, `size`, `read`, `write`, `execute`, `volatile`, `initialized`) + `getMemory().getBlocks()` in script · oracle: eval_response map · mutation: drop `volatile` field → assertion fails |
| 51 | `get_structures()` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_datatypes.py:406 `name`/`size`/`field_count` + :459 `getAllStructures` API in script + :428 empty-list case + :443 filter embedding · oracle: eval_response struct list · mutation: use `getDataTypes` instead of `getAllStructures` → script assertion fails |
| 52 | `get_bookmarks()` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_datatypes.py:533 `address`/`category`/`comment`/`type` fields + :560 category-filter embedding in script · oracle: eval_response bookmark list · mutation: drop `category` field → assertion fails |
| 53 | `delete_function(address)` (ghidra.py) | DISCONN-ONLY | RED_BY_DESIGN | test_ghidra_wave2a_edits.py:220 — PD-003: gate asserts `{"success": True, "address": addr}` but `prepare_remote_script` if/else never captures result → test is RED · PD-003 |
| 54 | `edit_function_signature(address, signature)` (ghidra.py) | DISCONN-ONLY | RED_BY_DESIGN | test_ghidra_wave2a_edits.py:274 — PD-003: gate asserts `{"success": True, "signature": sig}` but result-capture path broken → test is RED · PD-003 |
| 55 | `set_function_variable_type(address, var_name, type_name)` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_datatypes.py (test_set_function_variable_type_found_returns_success_dict) asserts `{"success": True}` + `getAllVariables` in script · oracle: eval_response bool · mutation: use `getVariableAt` instead of iterating `getAllVariables` → script assertion fails |
| 56 | `apply_structure_at(address, struct_name)` (ghidra.py) | DISCONN-ONLY | RED_BY_DESIGN | test_ghidra_wave2a_datatypes.py:479 — PD-003: gate asserts success dict but result-capture broken → test is RED · PD-003 |
| 57 | `get_sections()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test covers `get_sections` as a named method (distinct from `get_segments` and `get_memory_map`). No script framing or `SectionInfo` field assertions. Missing: `_FakeGhidraBridge` → assert `result[0].name == ".text"`. |
| 58 | `get_classes()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Script querying class hierarchy unverified. Missing: eval_response with class data → assert `result[0].name`. |
| 59 | `get_vtables()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response with vtable data → assert `result[0].address`. |
| 60 | `get_syscalls()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response with syscall list → assert `result[0].name`. |
| 61 | `get_callgraph(address, depth)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test covers connected-state callgraph. (Wave-2a_cfg.py covers `get_callers` which is different.) Missing: assert `getCalledFunctions` or equivalent API in script. |
| 62 | `get_relocations()` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_xrefs.py:168 `address`/`type`/`symbol`/`values` fields + `getRelocationTable` in script + :199 empty-list case · oracle: eval_response relocation list · mutation: drop `values` field → assertion fails |
| 63 | `get_resources()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test covers `get_resources`. Missing: eval_response with resource data → assert `result[0].type`. |
| 64 | `get_symbols()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test covers `get_symbols`. (xrefs.py covers `search_symbols` which is a different method.) Missing: assert `getAllSymbols` or `getSymbolTable` API in script. |
| 65 | `get_flags()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response with flag list → assert `result[0].name`. |
| 66 | `add_flag(address, name, size)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: assert `createLabel` or equivalent API call in script. |
| 67 | `get_types()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response with type list → assert `result[0].name`. |
| 68 | `get_function_graph(address)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response with graph nodes/edges → assert `result["nodes"]`. |
| 69 | `get_function_address(name)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response with address → assert `result == 0x401000`. |
| 70 | `get_all_strings()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found for `get_all_strings` as a named method (distinct from `search_strings`). Missing: eval_response string list → assert field values. |
| 71 | `get_libraries()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response with library list → assert `result[0].name`. |
| 72 | `get_headers()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response with header data → assert specific field. |
| 73 | `get_debug_info()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response with debug path/format → assert `result["debug_file"]`. |
| 74 | `get_comment(address)` (ghidra.py — singular) | DISCONN-ONLY | NOT_RESOLVED | Wave-2a datatypes.py covers `get_comments` (plural, address+range) and `get_all_comments` which are different methods. `get_comment` singular not covered. Missing: eval_response → assert `result.text`. |
| 75 | `get_namespace(name)` (ghidra.py — singular) | DISCONN-ONLY | NOT_RESOLVED | Wave-2a xrefs.py covers `get_namespaces` (plural) and `create_namespace` — both different methods. `get_namespace` singular not covered. Missing: eval_response → assert `result.path`. |
| 76 | `set_namespace(address, namespace)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: assert `setNamespace` or equivalent in script. |
| 77 | `get_data_references(address)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response reference list → assert `result[0].from_address`. |
| 78 | `get_instruction_at(address)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | Wave-2a cfg.py covers `get_instruction_flow` which is a different method. `get_instruction_at` single-address lookup not covered. Missing: eval_response instruction dict → assert `result["mnemonic"]`. |
| 79 | `get_bytes_at(address, length)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response hex bytes → assert `result == bytes.fromhex(...)`. |
| 80 | `write_bytes(address, data)` (ghidra.py) | DISCONN-ONLY | RESOLVED | test_ghidra_wave2a_edits.py:382 `setBytes` API in script + readback mismatch → ToolError at :418 + :447 invalid hex guard · oracle: hex encoding + readback comparison · mutation: use `patchBytes` instead of `setBytes` → script assertion fails |
| 81 | `patch_bytes(address, data)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found (distinct from `write_bytes`). Missing: eval_response → assert patch operation in script. |
| 82 | `get_register_values()` (ghidra.py — plural) | DISCONN-ONLY | NOT_RESOLVED | Wave-2a cfg.py covers `get_register_value` (singular) which is a different method. Plural variant not covered. Missing: eval_response register dict → assert `result["rax"] == 0`. |
| 83 | `emulate_function(address)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response with emulation state → assert `result["return_value"]`. |
| 84 | `get_stack_trace()` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | Wave-2a cfg.py covers `get_stack_frame` which is a different method. `get_stack_trace` not covered. Missing: eval_response frame list → assert `result[0]["function"]`. |
| 85 | `get_local_variables(address)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found (distinct from `set_function_variable_type`). Missing: eval_response variable list → assert `result[0]["name"]`. |
| 86 | `get_function_comments(address)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response comment list → assert `result[0]["text"]`. |
| 87 | `import_c_header(path)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test covers the Ghidra-side `import_c_header` (distinct from CutterBridge `import_c_header`). Missing: assert `CParser` or `parseHeaderFile` API in script. |
| 88 | `define_union(name, fields)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: assert `UnionDataType` construction in script. |
| 89 | `define_enum(name, base_type)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: assert `EnumDataType` construction in script. |
| 90 | `add_enum_value(enum_name, value_name, value)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: assert `add(value_name, value)` call in script. |
| 91 | `get_typedef(name)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: eval_response → assert `result["base_type"]`. |
| 92 | `create_typedef(name, base_type)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: assert `TypedefDataType` construction in script. |
| 93 | `delete_data_type(name)` (ghidra.py) | DISCONN-ONLY | NOT_RESOLVED | No wave-2a test found. Missing: assert `getDataTypeManager().remove(...)` in script. |
| **UI Panels — 4 findings** |||||
| 94 | `stack_viewer.py` — all operations (ui/panels/stack_viewer.py) | NO COVERAGE | NOT_RESOLVED | No test file found anywhere in `tests/`. `rg "StackViewer" tests/` returns no matches. No gate whatsoever. Missing: `StackViewer.set_frames` with real captured stack trace (list of `{"address": int, "symbol": str}`) → assert rendered row count and exact text. |
| 95 | `test_selection_dispatch.py` — `TestDocumentOpenedDispatch` + `TestCopyAsClipboardError` (c16_hex_panel_selection_dispatch/test_selection_dispatch.py) | MIXED (MagicMock/patch) | RESOLVED | File rewritten: `from unittest.mock import MagicMock, patch` removed; `TestDocumentOpenedDispatch` uses real `_CopyHarness` seam with `_get_clipboard`/`_write_to_clipboard`/`_warn_user` overrides; `TestCopyAsClipboardError` tests exact string and call-list values. `TestSelectionPropagation` (6 real gates) preserved. |
| 96 | `test_sandbox_panel_fixes.py` — combo + routing tests (tests/test_ui/test_sandbox_panel_fixes.py) | WEAK | NOT_RESOLVED | New behavioral tests added (`test_no_backend_shows_warning`: asserts `"No sandbox bridge configured" in output_text`; `test_create_success_handler_updates_ui`: asserts `panel._status_indicator.text() == "Active"`). But the original tautological tests remain (`test_selected_sandbox_type_windows` sets `"Windows Sandbox"` → asserts `_selected_sandbox_type()` returns `"windows"`: passes even if method body is `return "windows"` unconditionally). The specific `_on_save_to_sandbox` bridge routing test (audit P1 remediation target: assert bridge receives `copy_to` call with correct instance ID and destination) is still missing. |
| 97 | `async_bridge.py` — `cancel_pending_main_loop_tasks` + `shutdown_bridge_loop` (ui/panels/async_bridge.py) | NO COVERAGE | NOT_RESOLVED | `cancel_pending_main_loop_tasks` has no test: no test schedules a task, calls `cancel_pending_main_loop_tasks`, and asserts `task.cancelled()` is `True`. `shutdown_bridge_loop` tested for idempotency in `test_async_bridge.py` but `loop.is_closed()` is never asserted after shutdown. `_WorkerRegistry` GC retention not directly tested. Missing: schedule `asyncio.ensure_future(...)`, call `cancel_pending_main_loop_tasks()`, assert `task.cancelled()`. |

---

## STILL OPEN

The following 49 findings have no real falsifiable gate.

### CutterBridge (9 findings)

1. **`decompile(address)` (cutter.py:~650)** — happy path unverified. Only error-path test remains. Missing: recorder returning known C string → assert `result` contains known token (e.g., `"int main"`).

2. **`search_crypto_constants()` (cutter.py:3735)** — no test. Missing: recorder returning `[{"offset":4096,"name":"AES_SBOX"}]` for `/cj` command → assert `result[0].offset == 4096`.

3. **`search_magic()` (cutter.py:3752)** — no test. Missing: recorder returning magic match JSON for `/mj` → assert parsed `result[0].offset`.

4. **`search_value(value, size)` (cutter.py:3769)** — no test. Missing: assert `f"/vj4 {value}" in rec.commands` and parsed address list.

5. **`compare_bytes(hex_data, address)` (cutter.py:3791)** — no test. Missing: recorder returning comparison text → assert `result` matches expected diff output.

6. **`compare_disassembly(file_path, address)` (cutter.py:3812)** — no test. Two-command join (`cD` + `cCj`) logic unverified. Missing: assert both commands issued; assert joined `result`.

7. **`get_segments()` (cutter.py:3852)** — no test. Missing: recorder returning `iSSj` JSON → assert `result[0].name == ".text"`.

8. **`hexdump_words(address, length)` (cutter.py:3900)** — no test. Missing: assert `f"pxw {length} @ {address}" in rec.commands` (not `px`).

9. **`disassemble_function(address)` (cutter.py:3921)** — no test. Missing: recorder returning `pdf` text → assert `result` contains known mnemonic.

### GhidraBridge (37 findings)

10. **`analyze`** — no connected-state gate. Missing: `_FakeGhidraBridge` → assert `"AutoAnalysisManager"` or `"analyzeAll"` in script.

11. **`get_xrefs_from`** — no wave-2a coverage. Missing: eval_response ref list → assert `result[0].from_address`.

12. **`get_sections`** — no test (distinct from `get_segments`/`get_memory_map`). Missing: eval_response → assert `result[0].name == ".text"`.

13. **`get_classes`** — no test. Missing: eval_response → assert `result[0].name`.

14. **`get_vtables`** — no test. Missing: eval_response → assert `result[0].address`.

15. **`get_syscalls`** — no test. Missing: eval_response → assert `result[0].name`.

16. **`get_callgraph(address, depth)`** — no connected-state coverage (different from `get_call_graph` in section 1.3A). Missing: assert `getCalledFunctions` in script; assert callee list.

17. **`get_resources`** — no test. Missing: eval_response → assert `result[0].type`.

18. **`get_symbols`** — no test (distinct from `search_symbols`). Missing: assert `getAllSymbols`/`getSymbolTable` in script.

19. **`get_flags`** — no test. Missing: eval_response → assert `result[0].name`.

20. **`add_flag`** — no test. Missing: assert `createLabel` or equivalent in script.

21. **`get_types`** — no test. Missing: eval_response → assert `result[0].name`.

22. **`get_function_graph`** — no test. Missing: eval_response → assert `result["nodes"]`.

23. **`get_function_address`** — no test. Missing: eval_response → assert `result == 0x401000`.

24. **`get_all_strings`** — no test (distinct from `search_strings`). Missing: eval_response string list → assert field values.

25. **`get_libraries`** — no test. Missing: eval_response → assert `result[0].name`.

26. **`get_headers`** — no test. Missing: eval_response → assert specific header field.

27. **`get_debug_info`** — no test. Missing: eval_response → assert `result["debug_file"]`.

28. **`get_comment` (singular)** — wave-2a covers `get_comments` (plural) and `get_all_comments` — different methods. Missing: eval_response → assert `result.text`.

29. **`get_namespace` (singular)** — wave-2a covers `get_namespaces` (plural) and `create_namespace` — different methods. Missing: eval_response → assert `result.path`.

30. **`set_namespace`** — no test. Missing: assert `setParentNamespace` or equivalent in script.

31. **`get_data_references`** — no test. Missing: eval_response ref list → assert `result[0].from_address`.

32. **`get_instruction_at`** — wave-2a cfg.py covers `get_instruction_flow` which is different. Missing: single-address lookup in script → assert `result["mnemonic"]`.

33. **`get_bytes_at`** — no test. Missing: eval_response hex bytes → assert `result == bytes.fromhex(...)`.

34. **`patch_bytes`** — no test (distinct from `write_bytes`). Missing: assert patch API call in script.

35. **`get_register_values` (plural)** — wave-2a cfg.py covers `get_register_value` (singular) — different method. Missing: eval_response register dict → assert `result["rax"]`.

36. **`emulate_function`** — no test. Missing: eval_response state → assert `result["return_value"]`.

37. **`get_stack_trace`** — wave-2a cfg.py covers `get_stack_frame` — different method. Missing: eval_response frame list → assert `result[0]["function"]`.

38. **`get_local_variables`** — no test (distinct from `set_function_variable_type`). Missing: eval_response var list → assert `result[0]["name"]`.

39. **`get_function_comments`** — no test. Missing: eval_response → assert `result[0]["text"]`.

40. **`import_c_header`** (ghidra.py) — no test. Missing: assert `CParser` or `parseHeaderFile` in script.

41. **`define_union`** — no test. Missing: assert `UnionDataType` construction in script.

42. **`define_enum`** — no test. Missing: assert `EnumDataType` construction in script.

43. **`add_enum_value`** — no test. Missing: assert `add(value_name, value)` in script.

44. **`get_typedef`** — no test. Missing: eval_response → assert `result["base_type"]`.

45. **`create_typedef`** — no test. Missing: assert `TypedefDataType` construction in script.

46. **`delete_data_type`** — no test. Missing: assert `getDataTypeManager().remove(...)` in script.

### UI Panels (3 findings)

47. **`stack_viewer.py` zero coverage** — no test file. Missing: `StackViewer.set_frames` with real frame list → assert rendered item count and exact address/symbol text in first row.

48. **`test_sandbox_panel_fixes.py` bridge routing gap** — `_on_save_to_sandbox` bridge routing (`copy_to` dispatch) still ungated. Tautological combo tests remain. Missing: `SandboxPanel` with a real bridge stub → call `_on_save_to_sandbox()` → assert bridge `copy_to(instance_id, dst)` was called with expected args.

49. **`async_bridge.py` cancel/shutdown** — `cancel_pending_main_loop_tasks` not tested; `shutdown_bridge_loop` tested only for idempotency (no `loop.is_closed()` assertion); `_WorkerRegistry` GC retention not directly tested. Missing: schedule task → call `cancel_pending_main_loop_tasks()` → assert `task.cancelled() is True`.

---

## Counts

| Section | Total findings | RESOLVED | RED_BY_DESIGN | NOT_RESOLVED |
|---|---|---|---|---|
| §02 CutterBridge | 37 | 28 | 0 | 9 |
| §02 GhidraBridge | 56 | 15 | 4 | 37 |
| §15 UI Panels | 4 | 1 | 0 | 3 |
| **TOTAL** | **97** | **44** | **4** | **49** |
