# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [Unreleased]

### Added

- **mcp:** Add OAuth, resources and prompts, and Windows confinement (`b4d8258`)

- **ui:** Add MCP settings, consent, elicitation and transcript attribution (`7e24760`)

- **core:** Teach the orchestrator about third-party tool sources (`08be51b`)

- **mcp:** Present connected servers as ordinary Intellicrack tools (`9422992`)

- **core:** Let external tool sources reach the model, and record their state (`8627b45`)

- **mcp:** Add transports, tool catalogs, consent and connection lifecycle (`45290ac`)

- **mcp:** Add server configuration, input secrets and error types (`b84adde`)

- **providers:** Native large-toolset support on Messages and Responses (`ed04a5f`)

- **providers:** Make an arbitrary endpoint a first-class provider instance (`83475c7`)

- **providers:** Resolve model capabilities instead of guessing them (`e141161`)

- **core:** Ship the wire contract for externally-sourced tools (`ee229ea`)

- **providers:** Route every HTTP provider through its dialect adapter (`984fc30`)

- **providers:** Replace the provider enum with string instance ids (`bd6a266`)

- **core:** Implement dynamic tool loading and provider hardening (`6d92af5`)

- Expand bridge capabilities across dynamic and static tools (`0f75903`)

- **cutter:** 04-36+04-37+04-48+04-49 Cutter: manually add code/call/data cross-references (axc/axC/axd); Cutter: remove a cross-reference, optionally scoped to one source address (ax-); Cutter: relative seek stepping by a signed byte delta (sd); Cutter: seek-history navigation -- list, undo, redo (sh/shu/shr) (`2275cc4`)

- **frida:** 08-B2+08-D3+08-E5+08-E6+08-E10 Stalker call-summary tracing; Frida NativePointer typed read/write accessors as one coherent surface; Frida Module.enumerateRanges with a protection filter; Frida Module.enumerateSections and Module.enumerateDependencies; Frida single-export lookup via Module.findExportByName/getExportByName (`0e93305`)

- **x64dbg:** 02-A4+02-H7 x64dbg debug registers (DR0-DR7) and extended FPU/SIMD register read-write; x64dbg script engine single-step (DbgScriptStep) (`c7ff531`)

- **cutter:** 04-27+04-31+04-32+04-33 Cutter ESIL watchpoints on register/memory access (rizin 'de'); Cutter flag removal (rizin 'f-') via flags-table context menu; Cutter flag rename (rizin 'fr') via flags-table context menu; Cutter flagspace management (rizin 'fs'/'fslj'/'fs-') (`1b50f18`)

- **bridges:** 08-B2-prep add StalkerCallSummary for Stalker.follow onCallSummary mode (unblocks 08-B2) (`c8248be`)

- **bridges:** 08-E6-prep add ModuleSectionInfo and ModuleDependencyInfo for Module.enumerateSections/enumerateDependencies (unblocks 08-E6) (`f00c122`)

- **frida:** 08-A6+08-B3+08-B5+08-C5+08-C9 Interceptor.replaceFast low-overhead function replacement; Stalker.follow custom per-basic-block transform (StalkerTransformer); Independently callable Stalker.flush without stopping the trace; Read back live memory protection via Memory.queryProtection; Native in-process memory copy via Memory.copy (`b390fd2`)

- **ghidra:** 06-PT5+06-PT6+06-HS4+06-HS5 Ghidra create additional named program tree; Ghidra program-tree delete/rename and fragment-range assignment; Ghidra one-shot headless batch analysis with pre/post scripts; Ghidra configurable per-call analysis completion timeout (`1e394be`)

- **cutter:** 04-25+04-26 Initialize ESIL VM state distinct from memory init (Cutter/Rizin aei); Step ESIL emulation until a target address or expression (Cutter/Rizin aesu/aesue) (`8b4ce78`)

- **cutter:** 04-18+04-19 Discover attachable OS processes before attaching (Cutter/Rizin dpl/dplj); Send a signal to the attached debuggee process (Cutter/Rizin dk) (`8a76bc4`)

- **x64dbg:** 02-G6 x64dbg delete_label (labeldel) bridge method and Labels tab Delete control (`97851ea`)

- **x64dbg:** 02-G5 x64dbg delete_comment (commentdel) bridge method and Comments tab Delete control (`0e7db2b`)

- **x64dbg:** 02-D7 x64dbg create_thread/kill_thread (createthread/killthread) bridge methods and Threads tab Create/Kill controls (`c8982d6`)

- **x64dbg:** 02-C10 x64dbg load_library (loadlib) bridge method and Load DLL GUI control (`fd7ba08`)

- **bridges:** 08-A6-prep add HookInfo.original_trampoline so Interceptor.replaceFast can report its trampoline (unblocks 08-A6) (`0d89205`)

- **frida:** 07-D7+07-D8+07-D9+07-E2 Frida snapshot a warmed-up script VM and load a script from that snapshot; Frida attach a debugger/inspector to a running script; Frida forcibly terminate a hung script whose runtime never yields; Frida discover a running script's RPC exports (frida.list_rpc_exports) (`b6b6b5f`)

- **ghidra:** 06-DT11+06-MM6+06-MM7+06-MM9 Ghidra bulk data-type interchange: C header import and .gdt archive export/import; Ghidra move a memory block to a different start address; Ghidra rename a memory block and edit its comment; Ghidra non-default memory block creation (uninitialized, byte-mapped, bit-mapped) (`3b71862`)

- **x64dbg:** 01-H4 x64dbg coverage-boundary conditional tracing and trace-log-file redirection (`48598e5`)

- **x64dbg:** 01-H1+01-H2+01-H3+02-B5 x64dbg run to user code and to a caller-party boundary (RunToUserCode/RunToParty); x64dbg mode-restricted and exception-passthrough stepping (step into user/system code, extended step); x64dbg undo the last stepped instruction (InstrUndo); x64dbg memory page protection rights via setpagerights (`e9378a9`)

- **cutter:** 03-13+03-27+03-28+04-5+04-17 add the jsdec (pdd) alternate decompiler backend; apply FLIRT signatures to the loaded binary (Fs/Fa); create/export a FLIRT signature file from analyzed functions (Fc); conditional debugger continue (until syscall, call, or address); read the call stack / backtrace of the attached thread (`59f76ac`)

- **frida:** 07-B3+07-B8+07-C1+07-D6 capture spawned-process stdio via pipe mode; kill an arbitrary process (frida.kill); add session-scoped child-process gating; precompile Frida scripts to bytecode and load from precompiled bytes (`2a5e81d`)

- **x64dbg:** 01-E5 remove, enable, and disable exception breakpoints (remove_exception_config, enable_exception_config, disable_exception_config) (`4cf971a`)

- **x64dbg:** 01-D9+01-D10+01-E2+01-E3 reset a breakpoint's hit counter (reset_breakpoint_hit_count); set or clear a breakpoint's display name (set_breakpoint_name); remove a DLL breakpoint (remove_dll_breakpoint); enable and disable DLL breakpoints (enable_dll_breakpoint, disable_dll_breakpoint) (`f4924ba`)

- **ghidra:** 06-DT7 browse the full Data Type Manager category tree (not only structures) (`4e2f517`)

- **ghidra:** 05-6+05-7+06-CB4 add function tag management (create/assign/list FunctionTags); promote an existing symbol to primary in the Symbol Table; clear an existing comment at an address (remove_comment) (`bde1a1e`)

- **sandbox:** 10-17 sandbox per-instance isolation extras (`10fbedc`)

- **frida:** 07-A4+07-A5+07-A6+07-A9+07-B2 Frida remove/forget remote device; Frida device-change notifications; Frida device-lost notifications; Frida get frontmost application; Frida spawn with env/cwd overrides (`0c0db13`)

- **ghidra:** 05-1+05-2+05-3+05-4+05-5 Ghidra raw per-instruction P-code; Ghidra disassemble undefined bytes / clear code; Ghidra set context register over range; Ghidra rename parameter / local variable; Ghidra function flags no-return/var-args/inline (`83d239e`)

- **cutter:** 03-5+03-6+03-7+03-8+03-11 Cutter basic-block analysis pass (aab); Cutter function-call analysis pass (aac); Cutter reference analysis pass (aar); Cutter function autoname pass (aan); Cutter disassemble fixed byte range (pD) (`852c07a`)

- **x64dbg:** 01-D3+01-D5+01-D7 x64dbg breakpoint log condition; x64dbg breakpoint command condition; x64dbg breakpoint singleshot/silent flags (`6e70b06`)

- **x64dbg:** 01-C4+01-C8 x64dbg memory-range breakpoint (SetMemoryRangeBPX); x64dbg default breakpoint opcode type (SetBPXOptions) (`5180632`)

- **ui:** Add dark2/light2 theme assets required by the S19 four-theme gates (`90183f9`)

- **installer:** Log a per-step completion line with exit code and duration (`811f6ae`)

- **installer:** Log the full build pipeline and close a registry drift (`136785e`)

- **packaging,sandbox:** Relocate user state and add guest process picker (`dca310a`)

- **hexbench,core:** Enhance UI accessibility, packaging, and runtime bridges (`a78239d`)

- **x64dbg:** Arm x64dbg's trace record so hit counts can be non-zero (`8810140`)

- **hexbench:** Paint the design system's chart fill in the entropy map (`3b5a36a`)

- **hexbench:** Add hexbench web ui and harden hexcore concurrency (`2ac5a1a`)

- **sandbox:** Let a run bring the files its target cannot run without (`45f9ab4`)

- **sandbox:** Provision a Windows QEMU guest from discovered install media (`4c2fbe7`)

- Implement layout restoration toggle and model persistence (`921c7a4`)

- Complete tool bridge capabilities and integrate UI controls (`6bb308b`)

- Integrate workspace agents and update x64dbg plugin build (`d559b48`)

- **api:** Implement exponential backoff for rate-limited requests (`9bdda0c`)

- Implement Windows self-elevation and system theme tracking (`ec8a386`)

- Add autocomplete to HexPat pattern editor (`3f99127`)

- Add sandbox pause support and audit GPU BAR sizes (`1f64456`)

- **devtools:** Full flag passthrough for all lint recipes (`2e3975f`)

- **devtools:** Add -h/--help passthrough and recipe aliases (`a9abf28`)

- **devtools:** Add -h/--help passthrough and recipe aliases (`2241385`)

- **ui-logging:** Shard-20 audit - hex editor sub-modules (`5fa25d1`)

- **ui-logging:** Shard-15 audit — add workflow + entry/exit logs across UI surface (`2f49681`)

- Refactor Windows Docker entrypoint and add audit documentation (`f48c6bd`)

- Implement BitAndZero opcode in hexcore and compiler (`4c32f86`)

- Migrate test harness from Windows Sandbox to Docker (`2b13055`)

- **hexpat:** Parser — templates, varargs, padding, enum ranges, endianness, recovery (B27-B31, B37, B38) (`96364a3`)

- **hexpat:** Add optional span fields on parse/runtime errors (B36) (`bf3d808`)

- **hexpat:** Stdlib — math/hash/time/file/random/env/reflection + fixes (B39-B44) (`b73929a`)

- **hexcore:** Big-endian ELF support and Sym/Rel/Rela/Dyn/Nhdr templates (`98f361c`)

- **hexcore:** Add fat/universal Mach-O and 32-bit + common load commands (`92e3a36`)

- **hexcore:** Add ZIP64 structures and data descriptor templates (`907be1b`)

- **hexcore:** Strict AES-ECB padding modes and bit_shift overflow guard (`bd986b2`)

- **hexcore:** Patch export COD/JSON + fix IPS/IPS32 terminator collisions (`9afbff9`)

- **hexcore:** Support full Unicode in UTF-16LE string extractor (`098ab29`)

- Overhaul binary analysis architecture and expand tool bridges (`0d7ba70`)

- Auto-discover latest Gemini Flash model, fix blinter findings, update configs (`61cb6a1`)

- Add XPU status monitoring and bridge capabilities (`e1b7319`)

- Implement hexcore binary diffing and expand test coverage (`2c5b5c1`)

- Implement Hex Editor advanced analysis and pattern engine (`cf8a736`)


### Changed

- Apply linter cleanups and prune legacy launcher (`022499c`)

- **mcp:** Remove every suppression and the type errors behind them (`c0bad80`)

- Overhaul auto-save and introduce host-native test pass (`3b96c65`)

- Harden process isolation and tool integration (`4f5a4c7`)

- **x64dbg-plugin:** Relocate first-party bridge plugin from tools/ to src/ (`81576dc`)

- Remediate GUI responsiveness and layout issues from audit (`b1bfa87`)

- Remove HxD integration; native hex editor is canonical (`c08367b`)

- Fix win32 bridge integrations and strengthen test gates (`f1c3d35`)

- Harden test suite and fix win32 bridge defects (`7c07e36`)

- Harden test suite and integrate agent configurations (`dec2915`)

- Harden test suite and resolve core integration bugs (`c3daeb8`)

- Optimize kernel monitor sweeps and stabilize async bridge workers (`8830e8a`)

- Resolve audit findings and add real-data test coverage (`821c28f`)

- Simplify hexpat builtins and improve cutter operations (`8470818`)

- Clean up logging calls, error handling, and formatting (`31c3d23`)

- Modularize large bridge classes and rename internal modules (`ac65d54`)

- Decompose complex methods and upgrade dependencies (`5931e14`)

- Clean up unused assignments and fix google provider arguments (`7682e21`)

- Clean up logging, simplify conditional logic, and harden error handling (`dea440c`)

- **scripts/generate_tree:** Lazy-load tree rendering with flat JSON node table (`f3db7a3`)

- **bridges:** Consolidate PE format magic constants (audit Group 3) (`ae616ea`)

- **bridges:** Consolidate magic-byte format detection (audit Group 23) (`36dd136`)

- **bridges:** Consolidate PE machine->arch helper (audit Group 2) (`5c6cba4`)

- **ui:** Route hex editor PE/disasm/YARA through bridge (audit Group 22) (`8df55e4`)

- **hexpat:** Unify compiler with shared lexer/AST (audit Group 13) (`c9d9c10`)

- **providers:** Consolidate HTTP-status exception helper (audit Group 21) (`c10cda1`)

- **bridges:** Consolidate PE struct parsing helpers (audit Group 20) (`7c66abc`)

- **sandbox:** Consolidate log parsers (audit Group 10) (`ae4fe4d`)

- **ui:** Consolidate hex-editor QThread workers into GenericCallableWorker (`1b3dd7a`)

- **sandbox:** Consolidate network/YARA log helpers (audit Groups 11+12) (`b91ec7f`)

- **bridges:** Consolidate Win32 constants with INVALID_HANDLE_VALUE fix (audit Group 1) (`1e2d6fe`)

- **providers:** Consolidate streaming JSON parse-skip helper (`56a25e6`)

- **providers:** Consolidate OpenAI-format helpers (audit 4+5+6+8) (`5727b68`)

- **ui:** Consolidate hex-dump formatter helper (audit Group 14) (`8fc4e57`)

- **ui:** Consolidate dialog helpers full adoption (audit Group 16) (`22af53d`)

- **providers:** Consolidate tool-call parsing helper (audit Group 7) (`fa092f8`)

- Decommission basekit integration and update gitignore (`53e13e0`)

- **hexcore:** Replace naive byte/block diff with real edit script (`bdc3acf`)

- Fail loudly in piece_table delete when find_piece(end) returns None (`5866ccd`)

- Add docstrings and improve type safety in hexcore (`7ea2cd7`)

- Update knowledge graph and workspace configuration (`787845d`)

- Improve NUL file cleaning script efficiency (`dd41f43`)

- Update dependencies and modernize codebase (`5122c45`)

- Update commit message generator and project metadata (`b3d5d44`)

- Remove x64dbg plugin and restructure hex editor state (`c0640ca`)


### Documentation

- **notebooks:** Correct replace_bytes undo prose and cover the last 9 hexcore methods (`69d1422`)

- Add the cloud implementation brief for arbitrary AI provider support (`5be4580`)

- Generate API autosummaries and purge external tools (`4ba3ea6`)

- **readme:** Reframe scope around reverse engineering and binary analysis (`d7ef0dd`)

- Refine merge command execution parameters (`639dcc8`)

- Remove audit7.md report (`56e1b61`)

- **tests:** Drop orchestration placeholders from live test headers and function names (`618bc53`)

- Fix docstring findings in bridges (non-base) (`ef671d0`)

- Fix docstring findings in core orchestration (`cf324e5`)

- Fix docstring findings in tests/test_providers (`e8b0b75`)

- Fix docstring findings in tests/test_ui small + conftest (`3b11607`)

- Fix docstring findings in tests/test_ui large files (`59db4dc`)

- Fix docstring findings in ui/panels process_panel + remaining (`407801b`)

- Fix docstring findings in tests/test_core + test_sandbox (`1b2e054`)

- Fix docstring findings in bridges/base.py (`3dbf570`)

- Fix docstring findings in tests/test_bridges (`f9f51cc`)

- Fix docstring findings in providers (`e7c7e2f`)

- Fix docstring findings in tests/test_hexpat + test_scripts (`535c885`)

- Fix docstring findings in ui/panels cutter + hex_editor (`da89673`)


### Fixed

- **megalint:** Stop a Windows pixi path leaking into clippy, aim lychee's root (`da41a32`)

- **megalint:** Repair clippy, scope the project scanners, settle lychee (`a568ce2`)

- **megalint:** Write reports to the host instead of the container (`daf3147`)

- **tests:** Repair four worker constructions broken by the parent removal (`1927e87`)

- **tests:** Close two holes in the import-resolution gate (`e81057f`)

- **tests:** Repair the log viewer import that aborted pytest collection (`2820bf7`)

- **tests:** Stop the suite hanging at exit and contain Frida self-attach crashes (`541ef44`)

- **ui:** Stop Provider Settings destroying its own running worker threads (`27b02e9`)

- **providers:** Send o-series the token field it accepts; clear the stale tests (`c0ff41e`)

- **credentials:** Keep deliberate timeouts from v2 settings across the upgrade (`7cb62f1`)

- **providers:** Report an unreachable Grok endpoint as ProviderError (`3548757`)

- **tests:** Finish the provider-identity migration the rename left half-done (`198d397`)

- **providers:** Clear the type errors and two schema regressions on this branch (`79a6ec2`)

- **providers:** Give the OpenAI context window a stated fallback (`e81c363`)

- Restore the bindings this branch removed (`72f6cac`)

- Clear the type errors this branch introduced (`0477d61`)

- **core:** Persist multi-part tool-result content (`5f27665`)

- **core:** Persist reasoning blocks and keep one reserved-namespace list (`9c27b97`)

- **credentials:** Translate Win32 credential errors instead of leaking them (`d5faf4a`)

- **ui:** Stop hand-rolled worker threads dying with the widgets that start them (`6f15f0a`)

- **ui:** Stop callable-worker sites destroying the threads they start (`ceb6218`)

- **ui:** Stop the shared bridge dispatcher destroying its callers' workers (`11b6035`)

- **cutter:** ASCII labels for the relative-seek toolbar controls (`67622fb`)

- Harden bridge commands, UI overflow layout, and hexcore operations (`c855696`)

- Harden IPC pipe security and prevent arithmetic overflow panics (`c6b8146`)

- Resolve UI layout, bridge timeout, and session liveness issues (`72b0da4`)

- **packaging:** Restore full runtime declaration in [project.dependencies] (`8d5a94a`)

- **ui:** Guard hex strings worker probe against deleted C++ object (`b41886d`)

- **bridges:** Clear code units before write_bytes patches into disassembled code (`fa2bd18`)

- **ui,bridges:** Close out S19 RE-LIVE R01/R04-R07 and D-finding back-fills (`091e5e6`)

- **ui:** Commit R02/R03 input-field clipping fixes and extend gate to four themes (`2c372ee`)

- **tests:** Isolate host-native pytest basetemp and force ansi rendering (`40317b0`)

- **sandbox:** Quiesce the Docker engine before the host-native WHPX gates (`34ca26d`)

- **packaging:** Harden installer scripts and enforce runtime deps (`4eea4e7`)

- **ui, bridges, sandbox:** Stabilize UI states, error handling, and test runners (`6eb3723`)

- **sandbox:** Close a sandbox by its real window, and outlast the teardown (`0977e74`)

- **ui:** Re-enable sandbox controls to their backend-correct state after an op (`02339ad`)

- **ui:** Surface silent-but-successful and error script results in the Scripts panel (`5ed869c`)

- **sandbox:** Make the Windows guest provisioner able to actually install one (`b665cb0`)

- **sandbox:** Let the Host Compute Service finish before killing the worker (`44a5cd6`)

- **sandbox:** Wait for the collectors to report before reading the tabs (`51ff67b`)

- **sandbox:** Let a stopping QEMU sandbox still reach its guest (`80a41ef`)

- **sandbox:** Stage the configured folder on the guest's own volume, and fetch its output before it dies (`618b6be`)

- **sandbox:** Honour the shared folder, the telemetry toggle and the monitors the launcher could not start (`c899c1e`)

- **sandbox:** Honour the networking toggle, and stop reporting every Windows run as failed (`9f463d9`)

- **sandbox:** Read every lifecycle-reporting collector for outages, not half of them (`02d32bd`)

- **sandbox:** Load TraceEvent in the DLL monitor and stop losing its records (`1e161dd`)

- **sandbox:** Fetch the guest collectors' diagnostic logs, not only their data (`9516d42`)

- **sandbox:** Let the Windows ETW collectors consume events, and keep the tracer out of its own tab (`0eabf5f`)

- **qemu:** Serve the guest agent's command channel off its telemetry loop (`fb42363`)

- **qemu:** End the VM a failed start leaves running before removing its tree (`10b1c42`)

- **tests:** Register the S18-D05 async fixture and re-aim two vacuous gates (`602ae14`)

- **hexbench,sandbox:** Handle QEMU GA exec timeouts and improve UI accessibility (`6e3d791`)

- **qemu:** Outwait the Windows guest agent's serve cadence (S18-D04) (`83aac72`)

- **x64dbg:** Quote annotation writes and poll the async patch verify (`877bacb`)

- **hex-editor:** Align binary diff panel with engine schema (`db0b6bf`)

- **ui:** Share one ScriptManager between the Scripts panel and orchestrator (`50f8b45`)

- **ui:** Stop logging a routine provider failure as a worker crash (`e7fd98d`)

- **providers:** Surface why a provider rejected a call, with the key redacted (`c8f6cb6`)

- **ui:** Let the confirmation-level setting actually reach the orchestrator (`44fb453`)

- **session:** Keep a bridge analysis complete across a save and load (`6bf23d1`)

- **sandbox:** Pick the harness network from what the engine actually defines (`ee20fce`)

- **ui:** Stop the Analysis panel 32-bit address signal breaking its own construction (`361c541`)

- **ui:** Repopulate the chat panel when a saved session is loaded (`40a23c0`)

- **sandbox:** Stop the container harness starting a VM's neighbour on shared HCS (`472533c`)

- **sandbox:** Stop a routine guest-agent poll from logging a traceback (`a45b974`)

- **sandbox:** Let a Linux guest actually reach a listening monitor agent (`cc0b790`)

- **sandbox:** Make the provisioned guest answer to the name it was given (`cbb3dd9`)

- **sandbox:** Reap the sandbox session the Test Sandbox run started (`32679b3`)

- **sandbox:** Make the injection monitor's failure diagnostic name its statement (`a991b7d`)

- **sandbox:** Take a disk-only snapshot when the accelerator blocks machine state (`4ef8545`)

- **sandbox:** Stop reporting anti-evasion success when the guest work failed (`584dcd6`)

- **sandbox:** Stop reporting the deletion of a snapshot that never existed (`9269c76`)

- **sandbox:** Stop a dead injection monitor from accusing the sample (`e447e45`)

- **sandbox:** Start the machine again when a snapshot job stops it and fails (`5aacc7a`)

- **sandbox:** Make the guest agent and its two ETW collectors work at all (`c12171e`)

- **sandbox:** Stop asking vvfat to write, since it aborts the whole machine (`f2455cb`)

- **sandbox:** Notice when the QEMU hosting a run has died (`0e9ec55`)

- **sandbox:** Let a session survive losing the guest channel, without rerunning work (`1e6d4bc`)

- **sandbox:** Point WinPE at the driver folders the medium actually has (`657350a`)

- **sandbox:** Stop overwriting the good registry collector with the broken one (`c08f614`)

- **sandbox:** Let the guest's ETW recorders actually load the library they need (`41b5f9e`)

- **sandbox:** Stop a dead recorder from looking like a quiet one (`f388121`)

- **sandbox:** Give a QEMU guest run its registry, clipboard and nested staging back (`7ac26ef`)

- **sandbox:** Stop a byte-order mark corrupting the first record of every monitor log (`4fc8934`)

- **sandbox:** Make a ready guest agent one that has actually run a command (`ecaebb3`)

- **sandbox:** Stop reporting "nothing found" for scans and dumps that never ran (`aa53ac4`)

- **sandbox:** Let a caller say which sandbox a binary should run in (`6b4f658`)

- **sandbox:** Make a snapshot say what QEMU actually did with it (`4713223`)

- **sandbox:** Stop every sandbox writing to the one configured disk image (`30478c8`)

- **sandbox:** Stop spending the one guest-agent connection QEMU will give us (`97ace8b`)

- **sandbox:** Let the host pick QEMU's ports instead of hoping three are free (`a25cd30`)

- **sandbox:** Ask the guest to power off before ending its QEMU (`99dba1d`)

- **sandbox:** Give the guest agent the helper GLib needs to spawn anything (`71d42eb`)

- **sandbox:** Trust a driver catalog's whole chain, not just its signer (`6ce0f25`)

- **sandbox:** Give the guest a pointer that can be aimed (`656bb67`)

- **sandbox:** Install the virtio drivers this guest needs, without a prompt (`219f2f9`)

- **sandbox:** Give OOBE its own locale so the install finishes unattended (`bba65cb`)

- **sandbox:** Give a Windows guest the CPU and the interrupt chip it needs (`8a3c1f9`)

- **sandbox:** Let the Windows guest agent listen where the forward delivers (`41941a7`)

- **sandbox:** Make the monitor launcher wait for the monitors it started (`3de3e5c`)

- **sandbox:** Let a Linux guest fill the Network Activity and Resources tabs (`43302ee`)

- **sandbox:** Give every harness run its own identity so runs stop killing each other (`f1beac6`)

- **sandbox:** Stage a run's binary into the guest, not into a snapshot (`0cd22c6`)

- **sandbox:** Let a run reach the sandbox that is already running (`57a9a71`)

- **sandbox:** Prove the guest agent channel is live and report what ran on it (`6d994f9`)

- **ui:** Make the VM Display ask for a frame it can actually be given (`e12075f`)

- **sandbox:** Negotiate the guest-agent sync against what the agent really implements (`798bac3`)

- **sandbox:** Put qemu-guest-agent on its own channel and make the guest reach the share (`8cfa4d0`)

- **sandbox:** Make the QEMU backend launch on Windows (`06aecc8`)

- **sandbox,ui:** Surface sandbox failures, gate controls by backend, own restart (`2e0c146`)

- **sandbox:** Derive QEMU tools path from the project root, log the real VNC port (`2a788b4`)

- **sandbox,ui:** Converge the two divergent .wsb generators (`e19ef7a`)

- **sandbox,ui:** Make the QEMU backend reachable from the GUI (`ec6713d`)

- **sandbox:** Test Sandbox must verify a session, not process liveness (`6585609`)

- **sandbox:** Launch WindowsSandbox.exe, not the connection client (`e996961`)

- **bridges,ui:** Enumerate real x64 exception handlers for SEH tab (`5fe1cf4`)

- **bridges,core:** 64-bit VirtualAllocEx pointers, break bridges/core import cycle (`4a9bf44`)

- **ui:** Embed x64dbg window via desktop-scoped HWND lookup (`cd2b27d`)

- **ui:** Analysis no-backend notice, region popup decode, sandbox cleanup (`175b200`)

- **ui:** Editable, persisted user notes on Analysis panel (`b36be5e`)

- **ui:** Process-panel filtered counts + usable Pipes tab (`5fd9fcb`)

- **ui:** Restore chat + binary on Load Session, guard stale ids (`267d118`)

- **providers:** Surface OAuth client_id error, revoke API-key creds (`52bd8a5`)

- **ui:** Non-blocking attach confirmation in process panel (`df9943e`)

- **ui:** Xref/function-select signals carry 64-bit addresses (`e7c1e35`)

- **ui:** Load Binary dialog uses sized non-native QFileDialog (`4305d95`)

- **ui:** X64dbg panel reset views on stop + scrollable docked content (`696729c`)

- **providers:** HuggingFace served-model filter, Ollama loop-safe clients (`6657ec8`)

- **bridges,ui:** X64dbg watchpoints list via bp_list (`62bc57f`)

- **ui,bridges:** Frida hooks table, integer call returns, Advanced layout (`d66521a`)

- **bridges,ui:** Process section unmap + pattern-search cancel/progress (`e7e7bbf`)

- **bridges:** X64dbg Load registers attach state; headless Qt + modules (`c42d601`)

- **bridges,ui:** Process PID filter + raw-query sizing, Frida hooks (`8d56bad`)

- **core,ui,bridges:** Track attached PID, Frida console.log + backpressure (`341b973`)

- **bridges:** Cutter ROP gadgets, project round-trip, bytes search (`71ea329`)

- **core,bridges:** Streaming-on-tools, async Frida scan, robust unload (`ad4eadf`)

- **bridges,ui:** Cutter decompile/CFG, Ghidra read APIs, chat markdown (`3c4ae75`)

- **bridges,ui:** S13-S16 Phase 2 — Ghidra write-transactions, session rebind, Scripts New/Execute (`ea78b4d`)

- **providers:** S16 Phase 1 — safe .env template, tool-count caps, Gemini thought_signature (`95d4af0`)

- **tests:** Isolate local Ollama models and align device bridge permissions (`4c7d061`)

- Resolve named pipe concurrency, bridge lifecycle, and UI bugs (`38fe13b`)

- **deps:** Declare pygments as conda dependency to unblock requirements.txt (`5f74b87`)

- **ui:** Remediate 2026-07-01 GUI audit findings (`a75756c`)

- **core:** Resolve socket leak in connection pool shutdown (`beccc1f`)

- Resolve PE checksum offset defect and harden test suite (`27efe82`)

- **audit:** Update U24-a09 status.json and remediation report with re-fix attempt 2 results (`16bc834`)

- **ui:** Remove invalid keyword argument from setMouseTracking (`e35b5a2`)

- **audit/shard-16:** Add missing structured logs to provider config + process panel (`fd5611e`)

- **ui/process_panel:** F17 surface bridge errors with logger + QMessageBox (`80d0655`)

- **bridges:** F13 log silent excepts before re-raise (`0fdecab`)

- **logging:** F10 convert silent excepts to structured exception logs (`d199c68`)

- **sandbox:** F15 log silent excepts via shared optional-import helper (`b552dea`)

- **bridges/ghidra:** F11 log silent excepts before re-raise (`5b05beb`)

- **bridges/process:** F12 log silent excepts in process bridge (`303cdaa`)

- **providers:** F16 log silent excepts before re-raise (`cb581cc`)

- **core:** F14 log silent excepts in core modules (`c93dfec`)

- **sandbox/qemu:** F07 flatten logger extra={} kwargs into structlog kwargs (`06d16c1`)

- **hexpat:** F09 remove ImHex literal from interpreter path constants (`9201095`)

- **x64dbg:** Replace contextlib.suppress with explicit try/except + debug log (`4cf5a28`)

- **logging:** F05 canonical logger in huggingface/hex-editor silent excepts (`56fa37f`)

- **logging:** Satisfy RUF067 in intellicrack/__init__.py (`850e9b5`)

- **logging:** Resolve canonical logger pattern violations (F05) (`ea50010`)

- **bridges/hexpat/ui:** F02 safe_int_from_str + safe_call helpers, 22 sites (`f597268`)

- **ui/async_bridge:** F03 - run_bridge_coroutine_logged wrapper + rollout across all panels (`4ee82b3`)

- **audit-F01:** Log-and-reraise helper for typed-exception passthrough sites (`bd7d5cb`)

- **bridges/cutter:** MC-10 implement CutterBridge dynamic-analysis surface (`b864e71`)

- **ui/app:** MainWindow remediation U7 - status labels, signal lifecycle, provider/tool wiring, settings persistence (`8b8a43d`)

- **ui/overflow_toolbar:** Anchor combo popup to screen rect, close parent menu first — audit U9 (Cat-5 #8) (`d65b36b`)

- **ui/hex_editor:** Implement six empty stubs and clean up kwarg misuse - audit U1 (Cat-1 #1-6, Cat-2 #2) (`1c7e74b`)

- **ui/process_panel/memory:** Surface bridge errors via QMessageBox + logger — audit U5 (Cat-3 #1) (`b7b88fc`)

- **ui/hex_editor/sandbox:** Forward timeout to SandboxBridge.copy_to — audit U3 (Cat-9 #1) (`bc1556e`)

- **ui/x64dbg_panel:** Use direct setPlaceholderText, drop invalid kwargs — audit U11 (Cat-10 #1, Cat-2 same-file) (`f6b80a8`)

- **ui/stack_viewer:** Stop refresh timer on closeEvent, clean up kwargs — audit U10 (Cat-8 #1, Cat-2 same-file) (`c87a77c`)

- **ui/analysis_panel:** Surface invalid-address feedback, placeholder for notes, drop invalid kwargs - audit U8 (Cat-5 #4, #7, Cat-2 same-file) (`a6a2d4a`)

- **ui/hex_editor/yara:** Drop invalid PyQt6 keyword arguments — audit U2 (Cat-2 #3-4) (`e14f795`)

- **ui/ghidra_panel:** Remove dead graph_data assignment in _apply_cfg_blocks - audit U12 (Cat-10 #2) (`b4416f4`)

- **ui/process_panel/modules:** Add error handler for module enumeration — audit U6 (Cat-3 #2) (`a4ac973`)

- Refactor BPS/UPS patching and improve UI notification wiring (`323350c`)

- **sandbox-scripts:** Resolve all 12 blinter findings in monitor scripts (`59097e4`)

- **sandbox-bridge:** F-0010 symmetric BridgeState.last_error lifecycle (`291edd7`)

- **hexpat:** F-0007 wire std::print sink through UI panel and bridge (`5473c9e`)

- **bridges:** F-0008/F-0019/F-0035/F-0037/F-0044 process bridge audit7 (`563b03d`)

- **hex-editor:** F-0012/F-0017 fire TEMPLATE_REGISTERED on apply paths (`1ad6b7f`)

- **core-orchestration:** F-0007/F-0008/F-0022 wire tool_state, tag chips, fix YARA Protocol (`d04f6a1`)

- **x64dbg:** F-0001 verify 19 fire-and-forget wrappers post-condition (`b2da6e0`)

- **sandbox:** F-0019/F-0025 audit7 — coordinated monitor shutdown + dll_monitor structured unparsed records (`0b1173a`)

- **ui-app-core:** F-0021 wire wire_sandbox_backend through MainWindow + startup helper (`5c1a9fd`)

- **hex:** F-0042 stream BPS/UPS source via mmap to avoid full-file Python copy (`6fb62bf`)

- **sandbox:** F-0013/F-0021 windows.py WMI hijack + minidump target PID (`5593c93`)

- **ui-app-core:** F-0007 reuse prefetched status in ToolStatusDialog (`e9cbb06`)

- **qemu:** F-0022/F-0029 anti-evasion reg.exe allowlist + identity consistency (`932cb60`)

- **qemu:** F-0003 capture stdout/stderr in run_command fallback path (`9ed32fc`)

- **xml:** F-0011 replace __import__ obfuscation with direct xml.etree import (`d5d2ac3`)

- **process-panel:** F-0022/F-0023 add PID guards and user-visible error dialogs to SystemTab (`52168b9`)

- **providers:** F-0023 drop dead re-exports from package __init__ (`3637b70`)

- **qemu:** F-0007 wrap extract_dropped_files commands and add host fallback (`fa0bdb5`)

- **pyproject:** F-0001 prune dev packages from runtime dependencies (`2a68948`)

- **providers:** F-0021 invalidate discovery cache on unexpected exceptions (`51337a7`)

- **qemu:** F-0006 bootstrap guest agent via qemu-ga guest-exec (`16253cc`)

- **qemu:** F-0002 actually connect GuestAgentClient on sandbox start (`394cf67`)

- **ui:** F-0012 auto-refresh ThreadsTab combos via QTimer (`97d1b00`)

- **qemu:** F-0031 replace 2s sleep with file-stability poller (`b53e926`)

- **qemu:** F-0029 honor anti_evasion profile parameter (`f507c01`)

- **sandbox:** F-0001 prevent deadlock in SandboxManager.create eviction (`487cf82`)

- **hex_editor:** F-0040 strict ASCII-printable filter in UTF-16 scanner (`e298271`)

- **x64dbg:** Audit6 X64DBG-A — lifecycle/subprocess/platform (7 findings) (`dbe90b1`)

- **x64dbg:** Audit6 X64DBG-E - memory/PE/exports (F-0005/F-0019/F-0020/F-0021/F-0022) (`1c4d78d`)

- **ghidra:** Audit6 GHIDRA-D — parsing/xrefs/security/capability (5 findings) (`911dd68`)

- **x64dbg:** Audit6 X64DBG-D - concurrency/breakpoints (7 findings) (`d943a10`)

- **ghidra:** Audit6 GHIDRA-C — write methods + analyze (6 findings) (`8daae91`)

- **x64dbg:** Audit6 X64DBG-C - verification/logging/fallbacks (6 findings) (`1133531`)

- **core/orchestrator:** Audit6 CORE-B - agent loop (6 findings) (`b422ff5`)

- **ghidra:** Audit6 GHIDRA-B - headless launcher/lifecycle (9 findings) (`e92e6d4`)

- **core:** Audit6 CORE-D — config/process/tools/logging (9 findings) (`8a511a3`)

- **core/session:** Audit6 CORE-A - persistence/types (6 findings) (`3cf89b7`)

- **core/orchestrator:** Audit6 CORE-C - binary extraction/concurrency (4 findings) (`3e1f186`)

- **x64dbg:** Audit6 X64DBG-B - constants/PEB/anti-debug (4 findings) (`3a39d8a`)

- **ghidra:** Audit6 GHIDRA-A — remote_eval + dedent + read methods (7 findings) [foundation] (`bf3ce79`)

- **ui-mainwindow:** Audit5 u5 - wire orphan signals + repair menu/handlers (F-0001/F-0002/F-0003/F-0004/F-0006/F-0007/F-0008/F-0009/F-0010/F-0011/F-0012/F-0013/F-0014/F-0015/F-0016/F-0017/F-0018/F-0019/F-0023/F-0025/F-0026) (`b9e14a5`)

- **hexpat-core:** Audit5 u3 - wire stdlib/evaluator hooks and missing builtins (F-0001..F-0022, F-0025, F-0027) (`15b89ec`)

- **bridges-cutter:** Audit5 u1 - 15 findings (`8d05a91`)

- **bridges-frida:** Audit5 u2 — F-0005..F-0030 (18 findings) (`44424e1`)

- **hexpat-aux:** Audit5 u4 - parser/preprocessor/codegen fidelity (F-0023+F-0024+F-0026+F-0028) (`29c1ea7`)

- **ui-tools:** Audit5 u6 - populate function/xref panels and wire sandbox backend (F-0005, F-0021) (`40e092a`)

- **ui-confirmation:** Audit5 u9 - wire remember_similar through signal + cache (F-0020) (`0700993`)

- **ui-config-paths:** Audit5 u8 - replace hardcoded D:/Intellicrack defaults (F-0024) (`3d81cdc`)

- **ui-providerconfig:** Audit5 u7 - wire provider-specific resource links (F-0022) (`816dcd7`)

- **process-panel:** Audit4 B3+B7 — threads tab + workers (F-0011+0019+0026) (`2504369`)

- **process-panel:** Audit4 B1 - base status+controls (F-0001+F-0002+F-0025) (`5e8d52e`)

- **process-panel:** Audit4 B2 process tab (6 findings) (`a32b948`)

- **sandbox-qemu:** Audit4 A3 (16 findings) (`320579c`)

- **ui:** Audit4 C3 - hex data inspector F-0003/F-0011/F-0016 (`c5cb838`)

- **sandbox-windows:** Audit4 A4 — 15 findings (windows sandbox hardening) (`2bab06f`)

- **audit4:** C10 scripting + D1 pyproject restructure (F-0020+0021+pyproject-F-0001) (`899222e`)

- **hex-editor:** Audit4 C12 — sandbox bridge route (F-0006+0018+0019) (`20aa851`)

- **hex-editor:** Audit4 C8 (F-0023) -- offload signature scan from UI thread (`8cc1ff7`)

- **hex-editor:** Audit4 C16 - selection+dispatch (F-0004/F-0010/F-0024) (`5dd2622`)

- **process-panel:** Audit4 B5 — modules tab (F-0004+0024) (`51f8350`)

- **hex-editor:** Audit4 C6 (F-0003 hashing, F-0022) — notify + offload+stream CRC (`3daf281`)

- **hex-editor:** Audit4 C5 (F-0003 templates+pattern, F-0012, F-0017) (`a140e0e`)

- **hex-editor:** Audit4 C13 (F-0007) — route export/import patches through bridge (`00f7435`)

- **hex-editor:** Audit4 C11 (F-0005) — route open_process_memory through bridge (`51a8440`)

- **hex-editor:** Audit4 C9 (F-0013) — debounce follow-cursor disassembly (`ad45294`)

- **hex-editor:** Audit4 C15 (F-0009) — diff snapshot tempfile cleanup (`37e9971`)

- **hex-editor:** Audit4 resolves F-0003 (bookmarks slice) (`1231b6c`)

- **hex-editor:** Audit4 resolves F-0003 (transforms slice) (`e842031`)

- **hex-editor:** Audit4 resolves F-0002 F-0015 (`b20831c`)

- **hex-editor:** Audit4 resolves F-0001 F-0014 (`3cb044d`)

- **process-panel:** Audit4 resolves F-0020 F-0021 F-0022 F-0023 (`67f0acf`)

- **ui:** Audit4 B4 - MemoryTab F-0003/F-0005/F-0006/F-0007/F-0008/F-0009 (`b9635db`)

- **hex-editor:** Audit4 C14 resolves F-0008 (remove dead _ips module) (`256eee8`)

- **sandbox-analysis:** Audit4 A2 resolves F-0026 (hostname pattern over-broad) (`62860fe`)

- **sandbox-manager:** Audit4 A1 resolves F-0024+F-0032 (availability caching) (`148f6f9`)

- **sandbox:** Audit3 U7 - kernel+start monitors (F-0010 F-0021 F-0022 F-0023 F-0024 F-0025) (`e707ef6`)

- **ui:** Audit3 U11 - sandbox panel + vnc widget (`cfb2e30`)

- **core:** Audit3 U10 - disassembler+_xml_gen (F-0002 F-0009 F-0011) (`d740c16`)

- **ui:** Audit3 U13 - wire HxDPanel through panels package and MainWindow (F-0001) (`57165ba`)

- **core:** Audit3 U9 - aggregator+template (F-0005 F-0008 F-0015) (`f4fac55`)

- **sandbox:** Audit3 U4 - resource+service monitors (F-0005..F-0009) (`01b9fcb`)

- **core:** Audit3 U8 - script_gen.py 9 findings (`72a2814`)

- **ui:** Audit3 U12 - ghidra panel + script_manager template (`a98bb8d`)

- **named-pipe:** Audit3 U2 - named_pipe_client.py 16 findings (F-0010 F-0013 F-0014 F-0015 F-0016 F-0017 F-0019 F-0020 F-0021 F-0023 F-0024 F-0029 F-0032 F-0039 F-0040 F-0042) (`c02afed`)

- **sandbox:** Audit3 U5 - api_trace.ps1 (F-0011 F-0012 F-0013 F-0014) (`f0aef79`)

- **installer:** Audit3 U1 — installer.py 28 findings (F-0001 F-0002 F-0003 F-0004 F-0005 F-0006 F-0007 F-0008 F-0009 F-0011 F-0012 F-0018 F-0022 F-0025 F-0026 F-0027 F-0028 F-0030 F-0031 F-0033 F-0034 F-0035 F-0036 F-0037 F-0038 F-0041 F-0043 F-0044) (`c0858e2`)

- **sandbox:** Audit3 U6 - dll+injection monitors (F-0015 F-0016 F-0017 F-0018 F-0019 F-0020) (`1427ace`)

- **sandbox:** Audit3 U3 — clipboard_monitor.ps1 (F-0001 F-0002 F-0003 F-0004) (`6de3a64`)

- **bridges:** Rework audit2 Units 1/4/10 (14 findings, F-0013/0027/0029/0030/0031/0035/0038/0043/0044/0045) (`1b4977c`)

- **bridges:** Resolve audit2 F-0008/0009/0024/0025/0041/0042 (process-stack-seh-symbols-context) (`5ea1cba`)

- **bridges:** Resolve audit2 F-0001/F-0029/F-0044/F-0045 (process-init-lifecycle-logging) (`2a49737`)

- **process:** Audit2 F-0010/F-0020/F-0047/F-0048 (modules/threads/inject) (`014b9ba`)

- **bridges:** Correct PEB/TEB struct sizes, TLS array offsets, env block reads, WOW64 detection (audit F-0011/F-0012/F-0021/F-0022/F-0028/F-0033/F-0034/F-0046) (`1b865d4`)

- **bridges:** Process-com-dotnet audit findings F-0036 F-0014 F-0032 F-0015 (`c9e83f4`)

- **audit1:** All 7 units consolidated (88 findings + 1 escalated) (`17d21c8`)

- **process:** Resolve F-0002 F-0003 F-0019 F-0040 audit findings (`d1ac865`)

- **bridges:** Fix pipe/device handle validation, close reporting, IOCTL hex I/O (audit F-0016/17/18/26/37) (`ac4366d`)

- **sandbox-bridge:** Resolve audit findings F-0001 through F-0016 (`520e746`)

- **bridges:** Resolve audit2 process F-0006/F-0007/F-0037/F-0038/F-0039 (memory/sections) (`908d38e`)

- **providers:** Resolve audit2 providers F-0001..F-0024 (`a08278d`)

- **bridges:** Process control suspend/service audit fixes (F-0004/F-0005/F-0023/F-0026) (`91c51fe`)

- **semgrep-logging:** Bridges-process-rest (`5800ddc`)

- **semgrep-logging:** Bridges-base-cutter (`b6a67d7`)

- **semgrep-logging:** Credentials (`643d58f`)

- **semgrep-logging:** Ui-process-panel (`a71467f`)

- **semgrep-logging:** Ui-hex-panels (`c46ad81`)

- **semgrep-logging:** Ui-panels-toplevel (`9c6be1a`)

- **semgrep-logging:** Bridges-hex-editor (`d0e6af4`)

- **semgrep-logging:** Ui-toplevel (`3d80be7`)

- **semgrep-logging:** Main-entry (`af52aca`)

- **semgrep-logging:** Core-toplevel (`58d25f2`)

- **semgrep-logging:** Providers (`3b3201e`)

- **semgrep-logging:** Core-hexpat (`ff003bb`)

- **semgrep-logging:** Sandbox (`70bf5db`)

- **semgrep-logging:** Bridges/x64dbg.py (`39a1858`)

- **semgrep-logging:** Rule-design adjustments to eliminate ~125 false positives (`451f7c3`)

- **providers+credentials:** Remediate audit items C4, C5, C10, C11, C12, C13, C14, C15, C16, C17, C19, C29, C30, C31, C32, C33 (`9ea97eb`)

- **bridges:** Remediate audit items A1, A9, A14, A18, A21, A26, A32, A33, A35, A41, A44, A45, A46, A48, A52 (`06553b1`)

- **core+hexpat:** Remediate audit items B12, B18, B21, B22, B24, B25 (`db343ad`)

- Improve ghidra error handling and logging initialization (`d68c9c2`)

- **ui/ghidra_panel:** Dataclass program info, scoped refresh errors, non-empty xrefs, JSON analyzer options, batched comments (E31,E33-E37g,E41) (`0c17eb3`)

- **ui/hex/widget+highlighting+search:** Pattern offsets via search_hex, lazy color caches, clamp status, drop dead except (E61,E64,E65,E68) (`55ef65b`)

- **ui/hex/_transforms:** Route transforms + block ops through hexcore document (E55,E56) (`fa4fabd`)

- **ui/hex/_hashing:** Delegate hash + PE checksum to hexcore document (E59,E60) (`9b50c29`)

- **ui/hxd_panel:** Poll for HxD HWND and embed via win32 reparenting (E66) (`2497af9`)

- **ui/cutter_tabs:** Logged error callback for every cutter refresh (E38) (`3b6552f`)

- **ui/stack_viewer:** Instance-method Protocol + async get_stack_trace + state.is_ready/process_attached (E42-E45) (`690cba9`)

- **ui/tools+panel_dock+highlighter:** Sandbox_panel key, safe findChild, SSE/AVX/FPU ops, detached window cleanup (E23,E24,E27,E28,E30) (`831e69b`)

- **ui/sandbox_panel:** Populate instances tree + real snapshot row metadata (E72,E75) (`f782b03`)

- **ui/process_panel:** Relabel whole-process suspend/resume + wire SystemTab thread list (E73,E74) (`a18796d`)

- **ui/hex/_comparison:** Route byte-diff through HexEditorBridge.compare_files (E54) (`eda22a2`)

- **ui/hex/_sections:** Route string extraction through hexcore extract_strings (E51) (`e963d53`)

- **ui/xpu_status:** Type XPUDeviceInfo via TYPE_CHECKING import (E29) (`36aff3e`)

- **ui/vnc_widget:** RFB VNCAuth DES + bulk raw rect blit + async pumping (E69,E70,E71) (`52be5f5`)

- **ui/hex/_scripting:** AST-walker sandbox blocks attribute chains + gated writes (E67) (`78c0ee4`)

- **ui/hex/_data_inspector:** Hexcore bit/text codecs + list_encodings combo (E57,E58,E63) (`ac834b5`)

- **ui/hex/_patches:** Route IPS/BPS/UPS through hexcore (E52,E53) (`b1ade2e`)

- **ui/script_manager:** Set_language wires highlighter + rename dedup + execute dispatch (E46,E47,E48) (`65cd63c`)

- **ui/win32_embed:** Correct HWND handling and ctypes annotations (E25,E26) (`7ec3b96`)

- **ui/async_bridge:** Event sentinel prevents duplicate loop under parallel ensure (E76) (`68436bf`)

- **ui/frida_panel:** Persistent script handle + stalker invalid tid (E49,E50) (`55fbdc4`)

- **ui/cutter_panel:** Address parse, error status, decompile stale guard, empty xrefs (E32,E34,E35,E37) (`cb883e7`)

- **providers:** Rename _connected -> connected, add usage/thinking buffers, OpenAI-compat error mapping (C1-C3,C9-C13) (`d23d1db`)

- **credentials/env_loader:** Lossless round-trip with proper quoting and escape handling (C34) (`8cc3f9b`)

- **providers/huggingface:** Migrate to chat_completion API, map errors (C17-C19) (`7a4d1c6`)

- **providers/ollama:** Add missing endpoints, map errors, wire connection state (C14-C16) (`7778e0e`)

- **credentials/oauth:** Thread-safe singleton, PKCE validation, keyring errors (C25c, C30-C33) (`82c4158`)

- **providers/local:** Rename _connected → connected, fix device fallback + usage tracking (C20-C24) (`dde2351`)

- **credentials/store:** Fix list_providers deadlock, thread-safe singleton, handle KeyringError (C25b,C26-C29) (`3dcbf6d`)

- **providers/google:** Correct connection state, map errors, fix streaming usage (C4-C8) (`4747898`)

- **providers/registry:** Thread-safe singleton with double-checked locking (C25a) (`96e5ced`)

- **ui/preferences:** QFontComboBox monospace filter (E22) (`a842b61`)

- **installer:** Unit 9 A76 follow-up — remove DOC304 class-docstring Args (`37af610`)

- **sandbox:** Deep-review follow-ups on units 1-7 (D1-D19) (`ad5dd5e`)

- **frida:** Unit 5 A32 — hook/replace code delivery via script.post + recv (`c360ea1`)

- **sandbox:** Unit 1 — Windows Sandbox full rewrite (D1-D6, D12/D14/D19 Windows) (`636d378`)

- **sandbox:** Unit 5 — api_trace.ps1 rewrite (D16) (`66f8c11`)

- **sandbox:** Unit 2 — QEMU sandbox full rewrite (D7-D11, D12/D14/D19 QEMU) (`f1b3ff0`)

- **sandbox:** Rewrite kernel_object_monitor.ps1 with NT handle enumeration (D15) (`6efb207`)

- **sandbox:** Unit 7 — injection_monitor.ps1 (D18) (`5fdf6c8`)

- **sandbox:** Unit 6 — dll_monitor.ps1 (D17) (`dc0b4e2`)

- **sandbox:** Unit 3 - manager idleness tracking (D13) (`53613b2`)

- **bridges/ghidra:** Production-readiness remediation A1-A10 (#unit-1) (`901894f`)

- **hexpat:** Preprocessor include failure + function-like macro expansion (B34, B45, B46) (`e79b6c7`)

- **hexpat:** Evaluator — pointer deref, bitfield order, sizeof, cast, members, cleanup (B47,B49-B54) (`f2783a8`)

- **hexpat:** Cache max_magic_end in pattern registry (B55) (`eecdb83`)

- **core:** Enforce tool capability via explicit map (B2) (`afbba18`)

- **hexpat:** Lexer raises on stray '#' with directive hint (B33) (`bf9e762`)

- **hexpat:** Preserve pragma fields on base_address replace (B32, B48) (`3a8747c`)

- **core:** Orchestrator teardown, tool dispatch, context window (B3-B7, B10) (`9b20a81`)

- **core:** Script validators fail loud and typed API (B22, B26) (`7b8d03f`)

- **core:** Template bootstrap error aggregation (B21, B25) (`bff9099`)

- **core:** Persist bridge_analyses and guard session store (B1, B8, B9) (`7665f92`)

- **hexpat:** Compiler const-expr and conditional inversion (B23, B24) (`8a77024`)

- **core:** Harden process tracking and cleanup (B11, B13, B14, B16) (`0e6780b`)

- **core:** Config port fallback and unprefix parsers (B17, B19) (`93584c4`)

- **core:** Portable log directory (B12) (`3e07118`)

- **core:** Platform-guard subprocess constants (B15) (`4328412`)

- **core:** Make TransformNode abstract (B20) (`8adbf6a`)

- **hexpat:** Normalize document.length callable/property (B35) (`5ebc49e`)

- **hexcore:** Case-insensitive search handles mixed-case; strict ASCII encoder (`cdf30dd`)

- **hexcore/bps:** Fail loud on OOB and emit SourceCopy/TargetCopy (`7a39ffc`)

- **hexcore:** Align .pyi stubs with PyO3 signatures (`c8c4fc4`)

- **hexcore:** Record undo entries for swap_blocks, repair_pe_checksum, BPS/UPS imports (`ba163d0`)


### Performance

- **tests:** Isolate Frida self-attach modules per module, not per test (`8f4618d`)


### Security

- Declare core runtime dependencies and bump HTTP security floors (``)


