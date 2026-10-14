# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [Unreleased]

### Added

- **mcp:** Add OAuth, resources and prompts, and Windows confinement (`a8b0536`)

- **ui:** Add MCP settings, consent, elicitation and transcript attribution (`bacd429`)

- **core:** Teach the orchestrator about third-party tool sources (`68ebb9b`)

- **mcp:** Present connected servers as ordinary Intellicrack tools (`5ef22d4`)

- **core:** Let external tool sources reach the model, and record their state (`38df26e`)

- **mcp:** Add transports, tool catalogs, consent and connection lifecycle (`15d6968`)

- **mcp:** Add server configuration, input secrets and error types (`037ae6a`)

- **providers:** Native large-toolset support on Messages and Responses (`74a9738`)

- **providers:** Make an arbitrary endpoint a first-class provider instance (`e26b305`)

- **providers:** Resolve model capabilities instead of guessing them (`e572152`)

- **core:** Ship the wire contract for externally-sourced tools (`f9dc78c`)

- **providers:** Route every HTTP provider through its dialect adapter (`34dd571`)

- **providers:** Replace the provider enum with string instance ids (`7e776a2`)

- **core:** Implement dynamic tool loading and provider hardening (`aa297e5`)

- Expand bridge capabilities across dynamic and static tools (`932b455`)

- **cutter:** 04-36+04-37+04-48+04-49 Cutter: manually add code/call/data cross-references (axc/axC/axd); Cutter: remove a cross-reference, optionally scoped to one source address (ax-); Cutter: relative seek stepping by a signed byte delta (sd); Cutter: seek-history navigation -- list, undo, redo (sh/shu/shr) (`47290db`)

- **frida:** 08-B2+08-D3+08-E5+08-E6+08-E10 Stalker call-summary tracing; Frida NativePointer typed read/write accessors as one coherent surface; Frida Module.enumerateRanges with a protection filter; Frida Module.enumerateSections and Module.enumerateDependencies; Frida single-export lookup via Module.findExportByName/getExportByName (`500f996`)

- **x64dbg:** 02-A4+02-H7 x64dbg debug registers (DR0-DR7) and extended FPU/SIMD register read-write; x64dbg script engine single-step (DbgScriptStep) (`1a1228d`)

- **cutter:** 04-27+04-31+04-32+04-33 Cutter ESIL watchpoints on register/memory access (rizin 'de'); Cutter flag removal (rizin 'f-') via flags-table context menu; Cutter flag rename (rizin 'fr') via flags-table context menu; Cutter flagspace management (rizin 'fs'/'fslj'/'fs-') (`bdeb626`)

- **bridges:** 08-B2-prep add StalkerCallSummary for Stalker.follow onCallSummary mode (unblocks 08-B2) (`5a01da3`)

- **bridges:** 08-E6-prep add ModuleSectionInfo and ModuleDependencyInfo for Module.enumerateSections/enumerateDependencies (unblocks 08-E6) (`427b3a1`)

- **frida:** 08-A6+08-B3+08-B5+08-C5+08-C9 Interceptor.replaceFast low-overhead function replacement; Stalker.follow custom per-basic-block transform (StalkerTransformer); Independently callable Stalker.flush without stopping the trace; Read back live memory protection via Memory.queryProtection; Native in-process memory copy via Memory.copy (`2521357`)

- **ghidra:** 06-PT5+06-PT6+06-HS4+06-HS5 Ghidra create additional named program tree; Ghidra program-tree delete/rename and fragment-range assignment; Ghidra one-shot headless batch analysis with pre/post scripts; Ghidra configurable per-call analysis completion timeout (`00a6a4b`)

- **cutter:** 04-25+04-26 Initialize ESIL VM state distinct from memory init (Cutter/Rizin aei); Step ESIL emulation until a target address or expression (Cutter/Rizin aesu/aesue) (`f673156`)

- **cutter:** 04-18+04-19 Discover attachable OS processes before attaching (Cutter/Rizin dpl/dplj); Send a signal to the attached debuggee process (Cutter/Rizin dk) (`0a76e19`)

- **x64dbg:** 02-G6 x64dbg delete_label (labeldel) bridge method and Labels tab Delete control (`ecbafa3`)

- **x64dbg:** 02-G5 x64dbg delete_comment (commentdel) bridge method and Comments tab Delete control (`4bc08cb`)

- **x64dbg:** 02-D7 x64dbg create_thread/kill_thread (createthread/killthread) bridge methods and Threads tab Create/Kill controls (`62a7325`)

- **x64dbg:** 02-C10 x64dbg load_library (loadlib) bridge method and Load DLL GUI control (`40073fa`)

- **bridges:** 08-A6-prep add HookInfo.original_trampoline so Interceptor.replaceFast can report its trampoline (unblocks 08-A6) (`3fa2cc5`)

- **frida:** 07-D7+07-D8+07-D9+07-E2 Frida snapshot a warmed-up script VM and load a script from that snapshot; Frida attach a debugger/inspector to a running script; Frida forcibly terminate a hung script whose runtime never yields; Frida discover a running script's RPC exports (frida.list_rpc_exports) (`b6324e2`)

- **ghidra:** 06-DT11+06-MM6+06-MM7+06-MM9 Ghidra bulk data-type interchange: C header import and .gdt archive export/import; Ghidra move a memory block to a different start address; Ghidra rename a memory block and edit its comment; Ghidra non-default memory block creation (uninitialized, byte-mapped, bit-mapped) (`4338a96`)

- **x64dbg:** 01-H4 x64dbg coverage-boundary conditional tracing and trace-log-file redirection (`f8d6a85`)

- **x64dbg:** 01-H1+01-H2+01-H3+02-B5 x64dbg run to user code and to a caller-party boundary (RunToUserCode/RunToParty); x64dbg mode-restricted and exception-passthrough stepping (step into user/system code, extended step); x64dbg undo the last stepped instruction (InstrUndo); x64dbg memory page protection rights via setpagerights (`f0d4c28`)

- **cutter:** 03-13+03-27+03-28+04-5+04-17 add the jsdec (pdd) alternate decompiler backend; apply FLIRT signatures to the loaded binary (Fs/Fa); create/export a FLIRT signature file from analyzed functions (Fc); conditional debugger continue (until syscall, call, or address); read the call stack / backtrace of the attached thread (`b80492e`)

- **frida:** 07-B3+07-B8+07-C1+07-D6 capture spawned-process stdio via pipe mode; kill an arbitrary process (frida.kill); add session-scoped child-process gating; precompile Frida scripts to bytecode and load from precompiled bytes (`4ef2c42`)

- **x64dbg:** 01-E5 remove, enable, and disable exception breakpoints (remove_exception_config, enable_exception_config, disable_exception_config) (`1e9ec51`)

- **x64dbg:** 01-D9+01-D10+01-E2+01-E3 reset a breakpoint's hit counter (reset_breakpoint_hit_count); set or clear a breakpoint's display name (set_breakpoint_name); remove a DLL breakpoint (remove_dll_breakpoint); enable and disable DLL breakpoints (enable_dll_breakpoint, disable_dll_breakpoint) (`379e494`)

- **ghidra:** 06-DT7 browse the full Data Type Manager category tree (not only structures) (`79473eb`)

- **ghidra:** 05-6+05-7+06-CB4 add function tag management (create/assign/list FunctionTags); promote an existing symbol to primary in the Symbol Table; clear an existing comment at an address (remove_comment) (`30c2e88`)

- **sandbox:** 10-17 sandbox per-instance isolation extras (`55b61c0`)

- **frida:** 07-A4+07-A5+07-A6+07-A9+07-B2 Frida remove/forget remote device; Frida device-change notifications; Frida device-lost notifications; Frida get frontmost application; Frida spawn with env/cwd overrides (`94a9805`)

- **ghidra:** 05-1+05-2+05-3+05-4+05-5 Ghidra raw per-instruction P-code; Ghidra disassemble undefined bytes / clear code; Ghidra set context register over range; Ghidra rename parameter / local variable; Ghidra function flags no-return/var-args/inline (`ed851ef`)

- **cutter:** 03-5+03-6+03-7+03-8+03-11 Cutter basic-block analysis pass (aab); Cutter function-call analysis pass (aac); Cutter reference analysis pass (aar); Cutter function autoname pass (aan); Cutter disassemble fixed byte range (pD) (`b0ce825`)

- **x64dbg:** 01-D3+01-D5+01-D7 x64dbg breakpoint log condition; x64dbg breakpoint command condition; x64dbg breakpoint singleshot/silent flags (`4f29c26`)

- **x64dbg:** 01-C4+01-C8 x64dbg memory-range breakpoint (SetMemoryRangeBPX); x64dbg default breakpoint opcode type (SetBPXOptions) (`2cca8d9`)


### Changed

- Apply small Python modernizations across MCP, providers and tests (`11103d2`)

- **ui:** Take every Qt surface's colours, icons and styles from the theme system (`35c4353`)

- Apply linter cleanups and prune legacy launcher (`3bcf562`)

- **mcp:** Remove every suppression and the type errors behind them (`5835d3c`)


### Documentation

- **design-system:** Refresh tokens, component cards and gallery (`2ceb392`)

- Add the round-2 MCP and provider fix brief (`2e4586f`)

- **notebooks:** Correct replace_bytes undo prose and cover the last 9 hexcore methods (`c593f50`)

- Add the cloud implementation brief for arbitrary AI provider support (`76b9fe1`)

- Generate API autosummaries and purge external tools (`cdfd13d`)


### Fixed

- **ui:** Splash layout and theme tweaks (`fb448fa`)

- Isolate frida self-attach tests and rewrite sandbox argfiles (`bfdcd52`)

- **tests:** Report isolated Frida skips with the location tuple pytest requires (`89afb2a`)

- **tokens:** Bounded, non-blocking tiktoken loading with negative caching (`4287388`)

- **mcp/validation:** Principled ReDoS guard with hard match timeout; nullable and JSON equality (`fc8599e`)

- **json_schema:** Bound $ref inlining, honest strict flag, no empty Gemini OBJECTs (`d5b7066`)

- **mcp:** A missing mcp SDK disables MCP instead of breaking the UI (`cfc9278`)

- **ui:** Marshal MCP state onto the GUI thread and stop cleanly (`3398d11`)

- **ui:** MCP settings keep edits per server, track sign-in and running state, expose trust and prompts (`b8394a9`)

- **mcp:** Withdraw abandoned prompts, follow the elicitation schema, start servers side by side (`c07fb44`)

- **mcp:** Make consent, trust and approvals revocable and bound to what they were given for (`7ab166a`)

- **mcp:** Detect dead servers, follow changes across reconnects, exclude operator time (`f0dd2b2`)

- **mcp:** Confine sandboxed servers from creation with a restricted token (`4fe4cfd`)

- **mcp:** Use the SDK SSE client for sse servers and guard URL scheme logging (`9542881`)

- **config:** Default HuggingFace to the router host (`d28115f`)

- **credentials:** Stop storing a hash of chunked secrets (`3b173de`)

- **credentials:** Let a write replace an unreadable keyring entry (`c94ca57`)

- **mcp:** Accept other clients' mcp.json and check args for secrets (`4a0dba3`)

- **mcp:** Keep OAuth identity, registration and refresh across restarts (`f674bed`)

- **oauth:** Wait only for the real redirect and own the callback port (`3533d02`)

- **credentials:** Chunk large secrets and report keyring read failures (`6e766cd`)

- **providers:** Repair wire-format dialect replay, streaming errors and headers (`bae4b67`)

- **providers:** ConfigurableProvider HTTP layer and Gemini dialect (`97e05b8`)

- **mcp:** Route MCP tool results through multi-part content and fail calls, not turns (`e6ffab8`)

- **megalint:** Stop a Windows pixi path leaking into clippy, aim lychee's root (`716e290`)

- **megalint:** Repair clippy, scope the project scanners, settle lychee (`a21822a`)

- **megalint:** Write reports to the host instead of the container (`5275b93`)

- **tests:** Repair four worker constructions broken by the parent removal (`90576ea`)

- **tests:** Close two holes in the import-resolution gate (`0a532b7`)

- **tests:** Repair the log viewer import that aborted pytest collection (`1278898`)

- **tests:** Stop the suite hanging at exit and contain Frida self-attach crashes (`f13d70b`)

- **ui:** Stop Provider Settings destroying its own running worker threads (`6d23011`)

- **providers:** Send o-series the token field it accepts; clear the stale tests (`f0f3fbd`)

- **credentials:** Keep deliberate timeouts from v2 settings across the upgrade (`448a4e1`)

- **providers:** Report an unreachable Grok endpoint as ProviderError (`0361a2b`)

- **tests:** Finish the provider-identity migration the rename left half-done (`5c79079`)

- **providers:** Clear the type errors and two schema regressions on this branch (`a64c3bf`)

- **providers:** Give the OpenAI context window a stated fallback (`a7a5518`)

- Restore the bindings this branch removed (`56ee7be`)

- Clear the type errors this branch introduced (`68d644e`)

- **core:** Persist multi-part tool-result content (`ded1695`)

- **core:** Persist reasoning blocks and keep one reserved-namespace list (`11355a4`)

- **credentials:** Translate Win32 credential errors instead of leaking them (`8d17b59`)

- **ui:** Stop hand-rolled worker threads dying with the widgets that start them (`cc55bb0`)

- **ui:** Stop callable-worker sites destroying the threads they start (`7427310`)

- **ui:** Stop the shared bridge dispatcher destroying its callers' workers (`31a387f`)

- **cutter:** ASCII labels for the relative-seek toolbar controls (`e937f0f`)

- Harden bridge commands, UI overflow layout, and hexcore operations (`c5bef80`)

- Harden IPC pipe security and prevent arithmetic overflow panics (`0d747ae`)

- Resolve UI layout, bridge timeout, and session liveness issues (`6e38cf0`)

- **tests:** Isolate host-native pytest basetemp and force ansi rendering (`97c3247`)

- **sandbox:** Quiesce the Docker engine before the host-native WHPX gates (`eccfb7e`)


### Performance

- **tests:** Isolate Frida self-attach modules per module, not per test (`3fabcf0`)


### Security

- Fix Sonar Blocker findings, wire CI-based coverage import (`e204713`)

- Advanced CodeQL setup, harden .env perms, patch underscore CVEs (`5ac3fbe`)

- Declare core runtime dependencies and bump HTTP security floors (`474f1aa`)


