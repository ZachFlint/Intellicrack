# Intellicrack Functional-Audit Findings — Sorted by Implementation Effort

Companion document to `FUNCTIONAL_AUDIT.md` and `_category_grouped.md`. All 523
  global findings (F-0001 through F-0523) bucketed by **fix-effort estimate
only** — does not include test authoring, regression verification, or
integration soak time.

## Methodology

Each finding was assessed against three axes:

1. **Lines/files touched** (single-line vs whole-subsystem)
2. **Knowledge required** (mechanical fix vs domain expertise vs design decision)
3. **Blast radius** (self-contained vs cascades to N callers)

Estimates are wall-clock for a senior engineer who already knows the
codebase. They are **fix-only** — add another 30-100% for tests, code review,
and verification.

## Tiers

| Tier  | Label    | Range          | Typical work                                                             |
|-------|----------|----------------|--------------------------------------------------------------------------|
| **T1**| trivial  | 15 min – 1 hr  | Delete dead code, fix docstring, change log level, swap hardcoded const  |
| **T2**| small    | 1 – 4 hours    | Single-function rewrite, add validation, fix error handler, simple bug   |
| **T3**| medium   | 4 hr – 1 day   | Multi-method refactor, wire missing UI signal, implement small feature   |
| **T4**| large    | 1 – 3 days     | Whole-bridge refactor, new monitoring loop, asyncio redesign             |
| **T5**| epic     | 1+ weeks       | Subsystem rewrite, complete missing layer, spec-grade implementation     |
| **TBD**|investigate| design needed| Requires architectural choice or deeper investigation before estimable   |

## Aggregate Tally

| Tier | Count* | % of unique findings | Cumulative effort (low-high)     |
|------|--------|----------------------|----------------------------------|
| T1   | 171    | 32.7%                | 43 – 171 hours                   |
| T2   | 350    | 66.9%                | 350 – 1,400 hours                |
| T3   | 90     | 17.2%                | 360 – 720 hours                  |
| T4   | 45     | 8.6%                 | 360 – 1,080 hours                |
| T5   | 15     | 2.9%                 | 600 – 2,400+ hours               |
| TBD  | 4      | 0.8%                 | requires design decisions        |
| **Unique findings** | **523** | **100%** | **~1,700 – 5,800 person-hours** |

*Tier `Count` columns sum to **675**, not 523, because some findings span
multiple remediation aspects and appear in more than one tier subsection
(for example, a finding may have a T1 docstring fix and a separate T3
implementation fix). The unique-findings total of 523 matches
`_category_grouped.md`.

**Realistic project planning estimate** (fix + tests + review + verification):
roughly **3,000 – 9,400 person-hours**, dominated by the T4/T5 bucket
(Ghidra rewrite, x64dbg plugin/script split, HexPat std-lib, sandbox
guest-agent, ClamAV scanner, Mach-O support).

This document covers only findings whose target lives under `src/`,
`tests/`, or the root `pyproject.toml`. Findings against project
helper scripts (`scripts/**`), top-level type stubs (`typings/**`,
`stubs/**`), or docs/CI configuration are out of scope and do not
appear here.

---

# T1 — Trivial (171 findings)

Single-line, single-file, or pure-deletion work. Estimate range 15–60 minutes.

## T1: Dead code removal (delete-only)

- **F-0008** (cat 1) [sandbox-scripts] api_trace.ps1 `exit 0` masks setup failure — 15min — change exit code
- **F-0012** (cat 1) [ui-panels-hex] `_sandbox._do_save` ignores `_WDAG_PATH` semantics — 30min — fix path constant
- **F-0133** (cat 5) [core-hexpat] `set_print_sink` is dead code — 15min — delete or wire (T1 if delete)
- **F-0174** (cat 6) [ui-app-core] hardcoded D:/Intellicrack paths in defaults — 30min — env var lookup
- **F-0197** (cat 7) [providers-meta] `ModelDiscovery._lock` allocated never used — 15min — delete
- **F-0258** (cat 11) [sandbox-py] `WindowsSandbox.is_available` runs subprocess every call — 30min — cache result
- **F-0270** (cat 12) [core-orchestration] `_default_log_dir` uses `Path.cwd()` — 15min — use config value
- **F-0291** (cat 13) [core-analysis] `Script.save` logs before writing — 15min — move log
- **F-0292** (cat 13) [core-analysis] TemplateManager logs before write — 15min — move log
- **F-0293** (cat 13) [core-analysis] `disassemble_to_lines` constant `binary_path` log — 15min — fix log
- **F-0294** (cat 13) [core-analysis] `validate_javascript` duplicate cleanup logs — 15min — drop one
- **F-0295** (cat 13) [core-hexpat] legitimate break/continue logged at WARNING — 15min — change to DEBUG
- **F-0297** (cat 13) [core-orchestration] `tool_status_check_failed` wrong key naming — 15min — rename
- **F-0298** (cat 13) [providers-local] `_logger` instance reassignment loses binding — 15min — bind once
- **F-0302** (cat 13) [ui-app-core] `_on_provider_changed` only logs — 15min — wire to apply
- **F-0358** (cat 18) [providers-meta] `__init__.py` re-exports private TypedDicts — 15min — slim `__all__`
- **F-0357** (cat 18) [providers-meta] `get_provider_registry` not in `__init__` exports — 15min — add export
- **F-0444** (cat 20) [bridges-core] bridges/**init**.py re-exports unused — 30min — convert to lazy
- **F-0445** (cat 20) [bridges-cutter-frida] `r2.setter` never used — 15min — delete
- **F-0446** (cat 20) [bridges-ghidra] `supports_patching=True` but no patch method — 15min — flip flag
- **F-0447** (cat 20) [bridges-ghidra] `set_color` IntPropertyMap fallback returns success — 15min — drop fake-success
- **F-0448** (cat 20) [bridges-hex] `_alignment_grid_size` written never read — 15min — delete
- **F-0449** (cat 20) [bridges-installer] tool registry omits SANDBOX/HEX_EDITOR — 30min — add entries
- **F-0450** (cat 20) [bridges-installer] `_PLUGIN_ARCHS` third tuple field unused — 15min — drop field
- **F-0451** (cat 20) [bridges-x64dbg] `WIN_NO_INHERIT_HANDLE` constant suggests config — 15min — inline literal
- **F-0452** (cat 20) [core-hexpat] unreachable `_endian` fallback — 15min — delete
- **F-0453** (cat 20) [core-hexpat] `set_array_index` never called — 30min — wire or delete
- **F-0454** (cat 20) [core-orchestration] `Session.tool_states` never written — 30min — wire or delete
- **F-0455** (cat 20) [core-orchestration] `Session.tags` never assigned — 30min — wire or delete
- **F-0456** (cat 20) [core-orchestration] duplicate `Session` dataclass shadows real — 30min — delete shadow
- **F-0457** (cat 20) [providers-cloud] `get_pending_usage`/`get_pending_thinking` never consumed — 30min — wire to UI or delete
- **F-0458** (cat 20) [providers-local] dead constants `_B580_DEVICE_IDS` `_INTEL_VENDOR_ID` — 15min — delete
- **F-0459** (cat 20) [providers-meta] `_credential_loader` parameter never reached — 30min — wire or delete
- **F-0460** (cat 20) [sandbox-scripts] clipboard_monitor fallback unreachable — 15min — delete
- **F-0461** (cat 20) [sandbox-scripts] injection_monitor `$logmanStarted` for unused session — 15min — delete
- **F-0462** (cat 20) [sandbox-scripts] injection_monitor top-level `return` aborts — 15min — replace with throw
- **F-0463** (cat 20) [ui-app-core] `ToolConfirmationDialog.remember_similar` captured never read — 30min — wire or delete
- **F-0464** (cat 20) [ui-app-core] `wire_sandbox_backend` deprecated no-op — 15min — delete
- **F-0465** (cat 20) [ui-panels-hex] `_ips.py` 285-line module dead — 30min — delete file
- **F-0466** (cat 20) [ui-panels-hex] `refresh_pattern_highlights` calls update twice — 15min — drop one
- **F-0467** (cat 20) [ui-panels-main] HxDPanel implemented but never imported — 30min — wire or delete
- **F-0505** (cat 22) [core-analysis] inline comment in reload_script admits broken impl — 15min — fix or delete
- **F-0506** (cat 22) [hexcore-rust] `diff_data_block` block-level fallback dead — 15min — delete
- **F-0094** (cat 5) [bridges-core] `validate_tool_parameter` type check dead — 15min — restructure check

## T1: Logging / observability theater

- **F-0019** (cat 13) [bridges-hex] wholesale "everything changed" event after every modification — 30min — add range
- **F-0020** (cat 13) [bridges-hex] state-holder notified entire doc changed even on read-only script — 15min — gate on writes
- **F-0279** (cat 13) [bridges-core] `validate_and_convert` results computed only to log count — 30min — route schemas through
- **F-0280** (cat 13) [bridges-ghidra] `file_written` log without verifying write — 15min — move log
- **F-0281** (cat 13) [bridges-ghidra] `set_label`/`add_comment`/etc return `success: True` without verify — 1hr — add verification (per method)
- **F-0282** (cat 13) [bridges-hex] `apply_template` doesn't notify state holder — 15min — add notify
- **F-0285** (cat 13) [bridges-installer] per-chunk pipe write logging at INFO — 15min — change to DEBUG
- **F-0286** (cat 13) [bridges-installer] exception wrapped only as str(exc) — 15min — store traceback
- **F-0287** (cat 13) [bridges-process] every public method emits `_started` info events — 30min — change to DEBUG
- **F-0288** (cat 13) [bridges-process] dispatch shims emit duplicate `_started` events — 15min — drop one
- **F-0289** (cat 13) [bridges-sandbox] `is_available`/`status`/`list` log on every call — 15min — change to DEBUG
- **F-0290** (cat 13) [bridges-x64dbg] INFO logs claim success when only command queued — 30min — reword
- **F-0296** (cat 13) [core-orchestration] `_validate_tool_schemas` only logs warnings — 30min — reject broken schemas
- **F-0503** (cat 22) [bridges-ghidra] `analyze` writes `ghidra_analysis_complete` without distinguishing — 15min — fix log
- **F-0504** (cat 22) [bridges-hex] `run_python_script` forbidden_builtins set looks prototype — 30min — clean up

## T1: Documentation / signature drift fixes

- **F-0115** (cat 5) [bridges-installer] send_command Raises clauses missing — 15min — add
- **F-0468** (cat 21) [bridges-core] `protection_to_string` docstring lies about return shape — 15min — fix docstring
- **F-0469** (cat 21) [bridges-core] state/mem_type to_string silently bucket unknown — 30min — log and tag
- **F-0470** (cat 21) [bridges-cutter-frida] `assemble_at` returns bytes but doc says "Assembled bytes" — 15min — fix doc
- **F-0471** (cat 21) [bridges-ghidra] docstrings promise Raises ToolError but return empties — 30min — bulk fix docstrings (small if doc-only; T2 if behavior fix)
- **F-0472** (cat 21) [bridges-ghidra] `from_function`/`to_function` enrichment always None — 30min — drop or implement
- **F-0473** (cat 21) [bridges-hex] `toggle_bit` Rust path doesn't emit log — 15min — add log
- **F-0474** (cat 21) [bridges-hex] `search_numeric` accepts unknown value_type silently — 15min — validate
- **F-0475** (cat 21) [bridges-hex] `safe_print` ignores `file=` kwarg, no size cap — 30min — honour or doc
- **F-0476** (cat 21) [bridges-installer] send_command docstring missing Raises — 15min — add
- **F-0477** (cat 21) [bridges-installer] close() docstring omits I/O thread-pool side effects — 15min — add
- **F-0478** (cat 21) [bridges-installer] get_version docstring claims behaviour code doesn't deliver — 15min — fix doc
- **F-0479** (cat 21) [bridges-process] tool defs say "Success status" but always True — 30min — fix tool defs (per method)
- **F-0480** (cat 21) [bridges-process] `get_mitigation_policies` reports `enabled = bool(flags & 1)` — 30min — fix per-policy bit
- **F-0481** (cat 21) [bridges-process] tool defs claim "Hex string" but impls return bytes — 30min — convert in dispatch
- **F-0482** (cat 21) [bridges-sandbox] tool-def `default` values absent — 30min — add defaults
- **F-0483** (cat 21) [bridges-x64dbg] `set_breakpoint` advertises `condition` undocumented plugin contract — 30min — add bpcond fallback
- **F-0484** (cat 21) [bridges-x64dbg] `get_process_info` returns None but doc says ProcessInfo — 15min — raise instead
- **F-0485** (cat 21) [core-analysis] script_gen module docstring promises execution that doesn't exist — 15min — fix doc
- **F-0486** (cat 21) [core-analysis] `Script.created_at` naive datetime mixed with UTC — 15min — use UTC
- **F-0487** (cat 21) [core-hexpat] `std::string::parse_int` registered as `to_int` — 15min — register correct name
- **F-0488** (cat 21) [core-hexpat] missing `builtin::std::mem::*` callees referenced — 1hr — register missing names (T1 if shells; T3 if real impls)
- **F-0489** (cat 21) [core-hexpat] `_resolve_endian` docstring promises pragma-aware — 30min — implement or doc
- **F-0490** (cat 21) [core-hexpat] preprocessor discards `pragma.base_address` — 30min — preserve in emitted source
- **F-0492** (cat 21) [core-orchestration] system prompt instructs LLM on non-existent `binary.*` tools — 15min — fix prompt
- **F-0495** (cat 21) [sandbox-py] `time_limit` vs `timeout_seconds` mismatch — 30min — pick one
- **F-0208** (cat 8) [core-orchestration] HexDocument Protocol bodies provide concrete returns — 30min — replace with `...`
- **F-0207** (cat 8) [bridges-cutter-frida] frida.scan_memory pattern type mismatch — 15min — fix tool def

## T1: Build / metadata lies

- **F-0508** (cat 23) [bridges-hex] capabilities advertise macho/scripting — 15min — flip flags
- **F-0509** (cat 23) [config-pyproject] pyproject 95+ dev/test packages as runtime deps — 1hr — split extras

## T1: Recovery theater

- **F-0510** (cat 24) [bridges-core] ToolBridgeBase.shutdown does no real cleanup — 15min — make abstract
- **F-0512** (cat 24) [bridges-cutter-frida] shutdown calls super after releasing refs — 15min — reorder
- **F-0519** (cat 24) [bridges-x64dbg] get_status default-false indistinguishable from real — 15min — raise instead
- **F-0523** (cat 24) [providers-meta] connect_provider documents bool but never returns False — 15min — fix doc

## T1: Configuration / feature flag fixes

- **F-0265** (cat 12) [bridges-hex] `set_display_mode/set_color_mode` don't validate enum — 30min — add validation
- **F-0267** (cat 12) [core-hexpat] `BuiltinFunctions._endian` ignores `pragma.endian` — 30min — read pragma
- **F-0269** (cat 12) [core-orchestration] `_default_providers` omits HUGGINGFACE/GROK — 15min — add entries
- **F-0271** (cat 12) [providers-cloud] `enable_cache` discarded in OpenAI/Grok/OpenRouter/Google — 1hr — wire to SDK or raise
- **F-0272** (cat 12) [providers-cloud] `thinking` discarded in 4 providers — 1hr — wire or raise
- **F-0273** (cat 12) [sandbox-scripts] clipboard_monitor hardcoded log path — 15min — accept param
- **F-0274** (cat 12) [sandbox-scripts] resource_monitor hardcoded log path — 15min — accept param
- **F-0276** (cat 12) [sandbox-scripts] service_monitor hardcoded log path — 15min — accept param
- **F-0277** (cat 12) [sandbox-scripts] start_monitors.cmd default log dir contradicts scripts — 15min — fix path
- **F-0278** (cat 12) [sandbox-scripts] start_monitors no shutdown coordination — 30min — track PIDs

## T1: Single-line bug fixes

- **F-0093** (cat 4) [ui-panels-hex] `_disassembly._on_cursor_moved_disasm` per-cursor disassemble — 1hr — add debounce
- **F-0157** (cat 6) [bridges-installer] `_close_handle` doesn't check CloseHandle return — 15min — log on failure
- **F-0002** (cat 1) [bridges-process] `_acquire_queryable_job_handle` is documented stub — 2hr — implement via NtOpenJobObject + impersonation token (T2)
- **F-0507** (cat 22) [ui-panels-main] ScriptTypeInfo "x64dbg" template emits self-contradictory script — 1hr — rewrite template (T2)
- **F-0168** (cat 6) [bridges-x64dbg] read/write/alloc/free open new handle per call — 1hr — cache handle (small if simple cache)
- **F-0182** (cat 7) [bridges-hex] `_state_lock` only acquired in shutdown — 30min — drop or use everywhere
- **F-0183** (cat 7) [bridges-hex] hex_state `_notify` guard drops downstream events — 30min — propagate or queue
- **F-0184** (cat 7) [bridges-hex] hex_state set_document reads length outside lock — 15min — move inside
- **F-0185** (cat 7) [bridges-hex] hex_state asymmetric lock on display_mode — 15min — symmetric
- **F-0186** (cat 7) [bridges-hex] hex_state property getters read shared state without lock — 30min — add locks
- **F-0195** (cat 7) [hexcore-rust] `eval_pointer` swallows recursive errors — 15min — propagate via `?`
- **F-0235** (cat 9) [ui-panels-main] SandboxPanel VNC autoconnect doesn't forward password — 1hr — pipe password (T2 if widget API change)
- **F-0247** (cat 11) [core-analysis] reload_script ignores subdir saves — 30min — search
- **F-0254** (cat 11) [providers-meta] discover_one returns [] for unconnected — 15min — invalidate
- **F-0304** (cat 14) [bridges-cutter-frida] search_string_live unescaped user input — 30min — escape
- **F-0305** (cat 14) [bridges-ghidra] MD5 in BinaryInfo as integrity field — 15min — drop or label
- **F-0314** (cat 15) [bridges-ghidra] tempfile.gettempdir shared across instances — 30min — use mkdtemp
- **F-0315** (cat 15) [bridges-hex] list_process_regions docstring says Windows-only — 15min — add platform check
- **F-0316** (cat 15) [bridges-installer] common_paths POSIX entry for Ghidra — 15min — drop
- **F-0317** (cat 15) [bridges-installer] inconsistent os.name vs sys.platform — 15min — pick one
- **F-0318** (cat 15) [bridges-installer] vswhere PROGRAMFILES(X86) literal English — 15min — env var
- **F-0328** (cat 16) [bridges-hex] PE checksum offset hardcoded inline — 15min — use constant
- **F-0355** (cat 18) [bridges-hex] copy_as silently copies one byte at cursor — 15min — guard
- **F-0383** (cat 18) [ui-panels-hex] `_do_copy_as` swallows errors silently — 15min — surface
- **F-0392** (cat 18) [ui-panels-process] MemoryTab protect_tab missing placeholder — 15min — add hint
- **F-0405** (cat 18) [ui-panels-process] SystemTab privileges/PEB ignore `_attached_pid is None` — 30min — gate
- **F-0408** (cat 18) [ui-panels-process] `_update_controls_for_state` doesn't gate Process buttons — 30min — extend
- **F-0412** (cat 19) [bridges-cutter-frida] MemoryRegion always Windows constants — 15min — branch on platform
- **F-0413** (cat 19) [bridges-cutter-frida] Cutter is_64bit heuristic — 15min — also check `class`
- **F-0418** (cat 19) [bridges-installer] `_parse_version` returns 0,0,0 — 15min — raise
- **F-0419** (cat 19) [bridges-installer] x64dbg snapshot version date misparsed — 30min — branch
- **F-0427** (cat 19) [bridges-sandbox] yara_scan enum advertised but no validation — 15min — validate
- **F-0432** (cat 19) [core-hexpat] variadic params parsed but ignored at call — 1hr — implement (T2 if list build)

## T1: Misc

- **F-0003** (cat 1) [core-analysis] ScriptGenerator class is no-op shell — 30min — convert to module functions or delete
- **F-0004** (cat 1) [core-hexpat] `builtin_print` evaluator no-op — 15min — register `_io_print` under bare `print` (gated on F-0266)
- **F-0014** (cat 2) [bridges-cutter-frida] get_function returns hardcoded 0 for param/local sizes — 1hr — parse `afvd` properly
- **F-0225** (cat 5) [core-hexpat] compile_to_json swallows runtime errors as HexPatError — 15min — re-raise distinct types
- **F-0311** (cat 14) [hexcore-rust] swap_blocks silently zero-pads on length mismatch — 30min — add length-equality check + error
- **F-0502** (cat 22) [bridges-cutter-frida] hook_function leaks default console.log instrumentation — 30min — drop default or gate behind verbose flag
- **F-0017** (cat 2) [bridges-installer] PROCESS sentinel "builtin" path — 30min — typed sentinel
- **F-0018** (cat 2) [bridges-installer] Frida path literal "frida-python" — 30min — typed sentinel
- **F-0026** (cat 2) [core-hexpat] `_mem_base_address` hardwires 0 — 30min — wire pragma
- **F-0027** (cat 2) [core-hexpat] `_core_array_index` always 0 — 15min — wire stack
- **F-0028** (cat 2) [ui-panels-main] GhidraPanel labels use 0 fallback — 15min — refuse empty
- **F-0031** (cat 4) [bridges-cutter-frida] `get_function_address` enumerates all then filters — 30min — `afla`
- **F-0032** (cat 4) [bridges-cutter-frida] `search_strings` requires _analyzed unnecessarily — 15min — drop
- **F-0040** (cat 4) [bridges-hex] `snap_to_alignment` only floors — 15min — round
- **F-0047** (cat 4) [bridges-installer] `python`/`pip` instead of sys.executable — 15min — fix
- **F-0048** (cat 4) [bridges-installer] send_command increments id outside lock — 15min — move inside
- **F-0051** (cat 4) [bridges-process] `get_memory_map` hardcodes 0x40000/0x1000000 — 15min — use constants
- **F-0056** (cat 4) [bridges-process] `device_ioctl` accepts bytes but doc says hex — 30min — shim
- **F-0068** (cat 4) [core-orchestration] naive len // 4 token estimate — 30min — use tokenizer
- **F-0076** (cat 4) [providers-meta] `get_recommended_model` returns arbitrary first — 30min — raise
- **F-0077** (cat 4) [providers-meta] DiscoveryFilter uses pattern.match start-anchored — 15min — use search
- **F-0079** (cat 4) [providers-meta] DiscoveryCache.save_to_disk per-iteration time.time — 15min — snapshot
- **F-0114** (cat 5) [bridges-installer] `_find_frida` treats TimeoutExpired as missing — 15min — distinguish
- **F-0135** (cat 5) [providers-cloud] OpenAI chat_stream swallows transport errors on cancel — 15min — only swallow CancelledError
- **F-0136** (cat 5) [providers-local] `chat_template` access can raise AttributeError — 15min — guard
- **F-0137** (cat 5) [providers-local] `_check_rebar_status` parses PowerShell numeric output unsafely — 15min — try/except
- **F-0140** (cat 5) [providers-meta] ProviderError raised inside registry never carries provider_name — 30min — pass
- **F-0139** (cat 5) [providers-meta] disconnect_all aborts on first exception — 15min — collect-and-continue
- **F-0141** (cat 5) [providers-meta] DiscoveryFilter invalid regex degrades silently — 15min — fail closed
- **F-0142** (cat 5) [sandbox-scripts] clipboard_monitor blanket SilentlyContinue — 15min — switch to Stop
- **F-0143** (cat 5) [sandbox-scripts] service_monitor blanket SilentlyContinue — 15min — switch to Stop
- **F-0145** (cat 5) [ui-panels-hex] `_data_inspector._update_bit_buttons` returns early on first error — 15min — continue
- **F-0146** (cat 5) [ui-panels-hex] `_pattern_editor._on_pattern_apply` only emits notify from one path — 15min — emit from both
- **F-0189** (cat 7) [bridges-installer] download progress logging fires unreliably — 15min — switch to elapsed
- **F-0245** (cat 11) [bridges-process] suspend/resume swallow OpenThread/SuspendThread failures — 30min — propagate

---

# T2 — Small (350 findings)

Single-function rewrite, validation add, integration patch, error handler refactor.
1–4 hours per finding.

## T2: Hardcoded returns / fake success (correctness fixes)

- **F-0015** (cat 2) [bridges-hex] set_va_base claims success when backend lacks add_va_mapping — 1hr — return failure
- **F-0016** (cat 2) [bridges-hex] set_chunk_size/set_memory_budget return True regardless — 1hr — verify effect
- **F-0019** (cat 2) [bridges-installer] install_tool reports success when version unverifiable — 2hr — verify post-install
- **F-0020** (cat 2) [bridges-installer] _install_frida treats pip exit as installed — 2hr — check version returncode
- **F-0021** (cat 2) [bridges-x64dbg] Many wrappers return hardcoded `{"success": True}` — 4hr — verify each via post-condition (may need 1hr per wrapper × 20 = T4 in aggregate; T2 per individual)
- **F-0022** (cat 2) [bridges-x64dbg] set_breakpoint returns synthetic local id — 2hr — return native id
- **F-0023** (cat 2) [bridges-x64dbg] patch_anti_debug claims success on missing key — 2hr — fix PEB key + expand patch set (T3 if expand)
- **F-0024** (cat 2) [core-analysis] Default fallback architecture coerces to x86-64 — 1hr — raise instead
- **F-0025** (cat 2) [core-analysis] ScriptValidator.validate returns success for unknown — 30min — raise
- **F-0017** (cat 2) [bridges-installer] PROCESS sentinel — see T1

## T2: Naive implementations (single-function rewrites)

- **F-0030** (cat 4) [bridges-core] normalize_type silently downgrades to "string" — 1hr — raise + propagate
- **F-0033** (cat 4) [bridges-cutter-frida] get_classes returns raw `list[Any]` for methods/fields — 2hr — parse
- **F-0034** (cat 4) [bridges-ghidra] `_create_bridge_script` no encoding/OSError handling — 30min — add
- **F-0035** (cat 4) [bridges-ghidra] `search_bytes` silently returns [] for malformed hex — 1hr — raise
- **F-0037** (cat 4) [bridges-hex] ClamAV NDB scanner strips wildcards — 4hr — implement wildcard matcher (T3 if FSM)
- **F-0042** (cat 4) [bridges-hex] CRC fallback bit-by-bit Python — 1hr — use binascii/zlib fallback table
- **F-0043** (cat 4) [bridges-installer] x64dbg version_command "-v" launches GUI — 2hr — parse VERSIONINFO
- **F-0044** (cat 4) [bridges-installer] Cutter version GUI binary launch — 1hr — `--platform offscreen` or PE parse
- **F-0045** (cat 4) [bridges-installer] find_tool re-runs iterdir per executable — 1hr — single pass + nested
- **F-0046** (cat 4) [bridges-installer] GitHub asset selection fragile substring — 2hr — arch-aware
- **F-0049** (cat 4) [bridges-process] `_elevate_debug_privilege` ignores BOOL — 1hr — check
- **F-0050** (cat 4) [bridges-process] CreateToolhelp32Snapshot missing restype — 30min — set restype
- **F-0052** (cat 4) [bridges-process] `_scan_region_pattern` aborts entire region after one failure — 1hr — continue
- **F-0053** (cat 4) [bridges-process] enumerate_com_servers walks HKCR\CLSID synchronously — 2hr — to_thread
- **F-0054** (cat 4) [bridges-process] detect_dotnet hardcoded version string — 2hr — parse CLR header
- **F-0055** (cat 4) [bridges-process] CreateFileW missing restype = HANDLE — 30min — set restype
- **F-0057** (cat 4) [bridges-process] get_modules hardcodes entry_point=0 — 2hr — read PE
- **F-0058** (cat 4) [bridges-process] get_threads hardcodes current_pc=0 — 2hr — NtQueryInformationThread
- **F-0059** (cat 4) [bridges-sandbox] get_vnc_port no VNC support check — 1hr — gate
- **F-0060** (cat 4) [bridges-sandbox] pcap/screenshot/dump accept any sandbox without QEMU gating — 2hr — gate per method
- **F-0061** (cat 4) [bridges-sandbox] re-import sandbox.analysis on every call — 30min — cache
- **F-0062** (cat 4) [bridges-x64dbg] find_pattern wildcards reads only 1 MiB — 2hr — stream
- **F-0063** (cat 4) [bridges-x64dbg] get_threads placeholder fields — 2hr — query
- **F-0064** (cat 4) [bridges-x64dbg] `_read_module_entry_point` returns 0 silent — 2hr — proper PE parse
- **F-0065** (cat 4) [core-analysis] validate_java substring containment — 1hr — proper parse
- **F-0066** (cat 4) [core-analysis] Aggregator deduplicates imports/exports by address only — 1hr — natural key
- **F-0067** (cat 4) [core-hexpat] two divergent format implementations — 2hr — unify
- **F-0069** (cat 4) [core-orchestration] `_is_destructive_operation` substring matching — 1hr — explicit list
- **F-0070** (cat 4) [core-orchestration] missing context window disables trimming — 1hr — fail-closed
- **F-0071** (cat 4) [providers-cloud] Anthropic enable_cache only system prompt — 2hr — add tools+messages
- **F-0072** (cat 4) [providers-cloud] three identical _convert_tools impls — 1hr — DRY into base
- **F-0073** (cat 4) [providers-cloud] Anthropic connect probe limit=1 but pagination omits — 30min — add limit
- **F-0074** (cat 4) [providers-local] Default model silently substituted on empty input — 1hr — raise
- **F-0075** (cat 4) [providers-meta] `get_recommended_model` async never awaits — 30min — make sync
- **F-0078** (cat 4) [providers-meta] discover_one and discover_provider duplicate logic — 1hr — DRY
- **F-0080** (cat 4) [sandbox-py] `_poll_for_result` returns hardcoded empty stdout/stderr — 2hr — read script output
- **F-0084** (cat 4) [sandbox-py] extract_dropped_files ignores xcopy exit codes — 1hr — check
- **F-0085** (cat 4) [sandbox-py] list_snapshots parses QMP response incorrectly — 1hr — fix parser
- **F-0086** (cat 4) [sandbox-py] _DOMAIN_PATTERN matches .dll/.exe — 30min — anchor
- **F-0087** (cat 4) [sandbox-py] yara_scan falls back to scanning user input — 1hr — refuse
- **F-0088** (cat 4) [sandbox-py] QEMU yara_scan same defect — 1hr — refuse
- **F-0089** (cat 4) [sandbox-py] Windows run_binary always reports success — 1hr — gate on exit_code
- **F-0090** (cat 4) [sandbox-py] QEMU run_binary same defect — 1hr — gate
- **F-0091** (cat 4) [ui-app-core] `ProviderSettingsWidget` only wires three of seven providers — 2hr — wire remaining
- **F-0092** (cat 4) [ui-app-core] `_on_browse_models_result` opens dialog without provider context — 1hr — pass context
- **F-0166** (cat 6) [bridges-process] shutdown doesn't unmap sections / close pipes — 2hr — track
- **F-0169** (cat 6) [bridges-x64dbg] shutdown doesn't wrap _close_connection in try/except — 30min — try/finally
- **F-0170** (cat 6) [core-orchestration] `_atexit_cleanup` redundant termination work — 1hr — short-circuit
- **F-0171** (cat 6) [core-orchestration] Config.parse_providers drops user-defined providers — 1hr — preserve
- **F-0172** (cat 6) [core-orchestration] ToolRegistry.shutdown doesn't clear `_bridges` — 15min — clear
- **F-0173** (cat 6) [hexcore-rust] move_block missing undo for source clear — 2hr — add MoveBlock variant
- **F-0175** (cat 6) [ui-panels-hex] `_comparison.py` snapshot tempfile delete=False never cleaned — 30min — track + cleanup
- **F-0176** (cat 6) [ui-panels-hex] `_hashing._on_custom_crc` reads entire doc on UI thread — 2hr — worker
- **F-0177** (cat 6) [ui-panels-hex] `_signatures._on_scan_signatures` full doc on UI thread — 2hr — worker
- **F-0178** (cat 6) [ui-panels-main] SandboxPanel cleanup destroys without stopping PCAP — 1hr — stop first

## T2: Error handling refactors

- **F-0095** (cat 5) [bridges-cutter-frida] get_imports/exports/sections silently return [] — 1hr — raise distinct
- **F-0096** (cat 5) [bridges-cutter-frida] get_resources swallows ToolError — 30min — re-raise
- **F-0097** (cat 5) [bridges-cutter-frida] `_execute_script_and_wait` returns success after timeout — 2hr — fail
- **F-0098** (cat 5) [bridges-cutter-frida] allocate_memory loop doesn't break — 1hr — break
- **F-0099** (cat 5) [bridges-cutter-frida] attach calls initialize unconditionally — 1hr — guard
- **F-0100** (cat 5) [bridges-ghidra] functions swallow exceptions and return empty defaults — 4hr — distinct (T3 if many methods)
- **F-0101** (cat 5) [bridges-ghidra] decompile returns literal "Decompilation failed" — 30min — raise
- **F-0102** (cat 5) [bridges-ghidra] analyze claims success when analyzeAll never confirmed — 1hr — wait
- **F-0103** (cat 5) [bridges-hex] pattern registry unavailable returns empty — 30min — raise
- **F-0104** (cat 5) [bridges-hex] `_apply_arithmetic_fallback` silently returns input — 30min — raise
- **F-0105** (cat 5) [bridges-hex] PE structure bookmarks left half-applied — 1hr — transactional
- **F-0106** (cat 5) [bridges-hex] export_ips_patches falls back silently — 30min — raise
- **F-0107** (cat 5) [bridges-hex] search_text_encoded falls through silently if Rust raises — 30min — raise
- **F-0108** (cat 5) [bridges-hex] ClamAV DB load AttributeError on dict-shaped DB — 30min — guard
- **F-0109** (cat 5) [bridges-hex] ClamAV dispatch by suffix only — 1hr — content sniff
- **F-0110** (cat 5) [bridges-hex] base_convert raises uncaught ValueError — 15min — guard
- **F-0111** (cat 5) [bridges-hex] get_pe_imports DIRECTORY_ENTRY default magic fallback — 30min — fix
- **F-0112** (cat 5) [bridges-hex] run_python_script catches MemoryError, missing SystemExit/Overflow — 15min — add
- **F-0113** (cat 5) [bridges-installer] ensure_tool drops original install error — 30min — wrap
- **F-0116** (cat 5) [bridges-installer] event_handler exceptions corrupt request stream — 1hr — isolate
- **F-0117** (cat 5) [bridges-installer] close() does not wait for in-flight send_command — 1hr — drain
- **F-0118** (cat 5) [bridges-process] Process32First failure silently returns empty — 30min — distinguish
- **F-0119** (cat 5) [bridges-process] pipe_close/device_close always True — 30min — propagate
- **F-0120** (cat 5) [bridges-process] `_parse_registry_path` only three roots — 30min — add
- **F-0121** (cat 5) [bridges-process] reg_read_value treats ERROR_MORE_DATA as failure — 30min — retry
- **F-0122** (cat 5) [bridges-process] enumerate_com_servers returns [] when advapi32 unavailable — 30min — raise
- **F-0123** (cat 5) [bridges-process] create_section doesn't detect ALREADY_EXISTS — 30min — handle
- **F-0124** (cat 5) [bridges-process] query_system_info only retries on LENGTH_MISMATCH — 30min — broaden
- **F-0125** (cat 5) [bridges-sandbox] cont() only catches SandboxError — 30min — broaden
- **F-0126** (cat 5) [bridges-sandbox] analysis wrappers narrow except set — 1hr — broaden
- **F-0127** (cat 5) [bridges-sandbox] detect_behaviors silently discards bad rules — 1hr — error
- **F-0128** (cat 5) [bridges-sandbox] cont returns success=False without raising — 30min — fix
- **F-0129** (cat 5) [bridges-sandbox] get_pending_messages builds dict outside try — 30min — move
- **F-0130** (cat 5) [bridges-x64dbg] _is_recoverable_pipe_error matches by substring — 4hr — typed errors (T3 if plugin RPC change)
- **F-0131** (cat 5) [bridges-x64dbg] bare except Exception swallow paths — 2hr — narrow
- **F-0132** (cat 5) [core-hexpat] reflection provider hooks raise on every call — 1hr — provide stub provider
- **F-0134** (cat 5) [core-orchestration] auto-save loop dies silently on first failure — 30min — log + retry
- **F-0138** (cat 5) [providers-meta] connect_provider swallows wrong exception set — 30min — add ProviderError
- **F-0144** (cat 5) [ui-app-core] _refresh_system_status silently swallows errors — 30min — show + disable timer
- **F-0150** (cat 6) [bridges-ghidra] shutdown deletes bridge script without serialising — 1hr — lock
- **F-0149** (cat 6) [bridges-ghidra] shutdown doesn't close ghidra_bridge RPC client — 30min — close
- **F-0152** (cat 6) [bridges-hex] save_to_sandbox leaks created sandbox on copy_to failure — 30min — try/except
- **F-0151** (cat 6) [bridges-hex] open_file doesn't close previous document — 30min — close
- **F-0153** (cat 6) [bridges-hex] BPS/UPS export loads original + current docs simultaneously — 2hr — stream
- **F-0154** (cat 6) [bridges-hex] initialize replaces local cache, dropping rules — 30min — merge
- **F-0155** (cat 6) [bridges-hex] save_as doesn't update target_path — 15min — update
- **F-0156** (cat 6) [bridges-installer] cancelled connect() may leak pipe handle — 1hr — try/finally
- **F-0158** (cat 6) [bridges-installer] download_file leaves partial files on failure — 30min — temp + rename
- **F-0159** (cat 6) [bridges-installer] Unbounded growth of `_next_id` — 30min — wraparound
- **F-0160** (cat 6) [bridges-process] read_teb reads from `_process_handle` regardless of TID — 1hr — open per-TID
- **F-0161** (cat 6) [bridges-process] `_target_is_64bit` falls back to host pointer size — 30min — raise
- **F-0162** (cat 6) [bridges-process] map_section has no unmap_section — 2hr — add
- **F-0163** (cat 6) [bridges-process] get_handles walks by index without bounds — 30min — bound
- **F-0164** (cat 6) [bridges-process] stack_walk discards Suspend/SymInit BOOL — 30min — check
- **F-0165** (cat 6) [bridges-process] `_resolve_symbol` allocates only bare SYMBOL_INFO — 30min — proper buffer
- **F-0167** (cat 6) [bridges-sandbox] `_ensure_manager` re-creates singleton silently — 1hr — preserve
- **F-0180** (cat 7) [bridges-cutter-frida] payload waiter captures loop at construction — 1hr — pass loop
- **F-0179** (cat 7) [bridges-cutter-frida] Stalker.unfollow from separate script — 2hr — same script
- **F-0190** (cat 7) [bridges-process] async methods loop tens of thousands times block loop — 2hr — to_thread
- **F-0191** (cat 7) [bridges-x64dbg] _breakpoints/_watchpoints mutated from threads without lock — 2hr — call_soon_threadsafe
- **F-0192** (cat 7) [core-orchestration] shutdown/cancel race against pending confirmations — 2hr — drain
- **F-0193** (cat 7) [core-orchestration] SessionManager.update blocking SQLite on event loop — 2hr — to_thread
- **F-0194** (cat 7) [core-orchestration] `_signal_handler` synchronous fallback blocks — 1hr — schedule
- **F-0196** (cat 7) [providers-cloud] cancel_request no-op for non-streaming chat — 1hr — assign_current_task
- **F-0198** (cat 7) [providers-meta] DiscoveryCache get/set/invalidate skip lock on hot path — 30min — acquire
- **F-0199** (cat 7) [providers-meta] singleton no reset/teardown — 1hr — add reset
- **F-0200** (cat 7) [providers-meta] register/unregister/set_active mutate without lock — 30min — add lock
- **F-0202** (cat 7) [sandbox-scripts] service_monitor 2s polling loop racy — 2hr — Register-CimEvent
- **F-0203** (cat 7) [sandbox-scripts] kernel_object_monitor 3s polling misses transients — 2hr — ETW
- **F-0204** (cat 7) [sandbox-scripts] kernel_object_monitor OpenProcess(DUP_HANDLE) silent fail — 30min — log
- **F-0205** (cat 7) [sandbox-scripts] kernel_object_monitor never enables SeDebugPrivilege — 1hr — enable
- **F-0206** (cat 7) [ui-panels-hex] `_sandbox.execute_sandbox_operation` new asyncio loop per call — 1hr — reuse
- **F-0218** (cat 9) [bridges-installer] `_open_handle` share_mode=0 blocks reconnects — 30min — share read
- **F-0219** (cat 9) [bridges-installer] deploy_x64dbg_plugin needs Program Files write without admin check — 1hr — check
- **F-0220** (cat 9) [bridges-installer] cmake/build feedback dropped on plugin build failure — 1hr — capture
- **F-0227** (cat 9) [core-orchestration] Cutter bridge never auto-initialized — 1hr — wire
- **F-0229** (cat 9) [sandbox-scripts] start_monitors fire-and-forget no PID tracking — 1hr — track
- **F-0230** (cat 9) [ui-panels-hex] highlight rules update only local widget never bridge — 1hr — wire
- **F-0231** (cat 9) [ui-panels-hex] `_process_memory.py` bypasses bridge replaces document — 2hr — route via bridge
- **F-0233** (cat 9) [ui-panels-hex] IPS/BPS/UPS export+import bypass bridge — 2hr — route
- **F-0234** (cat 9) [ui-panels-hex] `_data_inspector._on_encode_text` falls back to class encoder — 30min — guard
- **F-0236** (cat 10) [bridges-ghidra] Popen invocation lacks cwd/env scrub/CREATE_NO_WINDOW — 30min — add
- **F-0237** (cat 10) [bridges-ghidra] start_headless `analyzeHeadless.bat` POSIX fallback — 30min — platform-aware
- **F-0238** (cat 10) [bridges-installer] cmake configure timeout (120s) too tight — 30min — bump
- **F-0239** (cat 10) [bridges-installer] _find_cmake silently returns None on vswhere failure — 30min — propagate
- **F-0240** (cat 10) [bridges-x64dbg] `_start_debugger` PIPE pipes never drained — 30min — DEVNULL
- **F-0241** (cat 11) [bridges-cutter-frida] `_alloc_scripts` mapping never GCs entries — 1hr — track unload
- **F-0242** (cat 11) [bridges-hex] target_path constructed twice can drift — 30min — single source
- **F-0243** (cat 11) [bridges-hex] hex_state clear_all only emits DOCUMENT_CLOSED — 30min — fire highlight
- **F-0244** (cat 11) [bridges-process] terminate always tears down bridge handle on failure — 30min — gate
- **F-0246** (cat 11) [bridges-sandbox] BridgeState wired once never updated — 1hr — wire
- **F-0248** (cat 11) [core-orchestration] load_session never starts auto-save — 30min — wire
- **F-0249** (cat 11) [core-orchestration] User message persists even when agent loop fails — 1hr — transactional
- **F-0250** (cat 11) [core-orchestration] register_external_pid doesn't verify PID exists — 30min — verify
- **F-0251** (cat 11) [providers-meta] DiscoveryCache stores empty model lists — 30min — exclude
- **F-0252** (cat 11) [providers-meta] discover_all stale cache leak — 1hr — fix semantics
- **F-0253** (cat 11) [providers-meta] disconnect_provider doesn't clear `_active_provider` — 30min — clear
- **F-0255** (cat 11) [providers-meta] DiscoveryCache.load_from_disk partially overwrites — 1hr — atomic
- **F-0256** (cat 11) [providers-meta] discover_all records errors but doesn't invalidate cache — 30min — invalidate
- **F-0257** (cat 11) [sandbox-py] start() redoes accelerator detection — 30min — cache
- **F-0259** (cat 11) [ui-panels-hex] document mutations skip notify_data_modified in 5+ mixins — 2hr — wire
- **F-0260** (cat 11) [ui-panels-hex] `_on_selection_changed` selection stored locally only — 30min — propagate
- **F-0261** (cat 11) [ui-panels-hex] panel.py save path stops listening for DOCUMENT_OPENED — 30min — drop guard
- **F-0262** (cat 11) [ui-panels-hex] pattern editor and templates partial sync — 1hr — full sync
- **F-0263** (cat 11) [ui-panels-hex] `_search` results not cleared when changing modes — 30min — clear
- **F-0264** (cat 11) [ui-panels-main] SandboxPanel snapshot leaves _pending_snapshot_label — 30min — clear
- **F-0266** (cat 12) [core-hexpat] `std::core::set_endian` doesn't affect struct reads — 1hr — wire to evaluator
- **F-0268** (cat 12) [core-hexpat] eval_depth default 32 trips on common patterns — 30min — bump default
- **F-0275** (cat 12) [sandbox-scripts] resource_monitor SilentlyContinue hides counter failures — 30min — fail loud
- **F-0283** (cat 13) [bridges-hex] wholesale change event after every modification — see T1 (F-0021 dup)
- **F-0284** (cat 13) [bridges-hex] state holder notified entire doc even when script didn't write — see T1
- **F-0303** (cat 14) [bridges-cutter-frida] JS template strings interpolate ints without int() — 1hr — int()/escape
- **F-0306** (cat 14) [bridges-ghidra] import_debug_info passes path without canonicalisation — 30min — Path.resolve + check
- **F-0308** (cat 14) [bridges-hex] MD5 of full file in memory defeats mmap — 1hr — chunk read
- **F-0309** (cat 14) [bridges-hex] export_annotated_html escapes only 3 chars; bookmark color XSS — 30min — proper escape
- **F-0310** (cat 14) [core-analysis] _xml_gen obfuscates xml.etree to evade bandit — 30min — use defusedxml
- **F-0312** (cat 14) [hexcore-rust] `sizeof()` silently returns 0 — 30min — error
- **F-0313** (cat 14) [sandbox-py] `_dispatcher_ps1_source` catch swallows all errors — 30min — narrow
- **F-0319** (cat 15) [bridges-x64dbg] `_wait_for_pipe_ready` non-Windows fallback to sleep — 15min — raise
- **F-0320** (cat 15) [bridges-x64dbg] `_detect_process_arch` defaults to 64-bit on error — 30min — raise
- **F-0321** (cat 15) [sandbox-py] `-cpu host` requires HW virt — 1hr — branch on accel
- **F-0322** (cat 15) [sandbox-py] SMB shared folder unavailable on Windows-host — 2hr — fall back to virtio-9p or vsock
- **F-0324** (cat 16) [bridges-cutter-frida] assemble_at writes bytes twice (wa then wx) — 30min — drop one
- **F-0327** (cat 16) [bridges-hex] yara_scan loads entire document — 2hr — chunked
- **F-0329** (cat 16) [bridges-hex] entropy/digram require exact Rust attribute names — 1hr — getattr fallback
- **F-0332** (cat 16) [bridges-hex] UTF-16 scanner accepts code units like 0x2070 — 30min — better classifier
- **F-0333** (cat 16) [bridges-installer] get_version subprocess can launch GUI tools — 1hr — gate
- **F-0334** (cat 16) [bridges-process] get_seh_chain x86-only but exposed for arbitrary TIDs — 30min — gate
- **F-0335** (cat 16) [bridges-process] thread_context picks 64/32 by host pointer — 1hr — IsWow64Process2
- **F-0336** (cat 16) [bridges-process] inject_dll discards WaitForSingleObject return; ANSI API — 1hr — use W + check
- **F-0337** (cat 16) [bridges-process] read_peb/read_teb fixed 0x100 buffer — 30min — bigger or paged
- **F-0338** (cat 16) [bridges-process] get_handles returns raw ObjectTypeIndex — 2hr — NtQueryObject
- **F-0339** (cat 16) [bridges-process] `_query_thread_state` Suspend-then-Resume can leave suspended — 30min — try/finally
- **F-0340** (cat 16) [bridges-process] get_tls_values reads from expansion slot pointer — 1hr — use static slots
- **F-0341** (cat 16) [bridges-process] `_parse_teb_fields` mislabels TEB+0x58 — 15min — fix label
- **F-0342** (cat 16) [bridges-x64dbg] get_resources only walks top level — 2hr — recurse
- **F-0343** (cat 16) [bridges-x64dbg] `_build_export_entries` truncates at 4096 silently — 30min — log + remove cap
- **F-0344** (cat 16) [bridges-x64dbg] analyze_entropy reads entire region in one call — 1hr — chunked
- **F-0345** (cat 16) [core-orchestration] `_extract_imports`/`_extract_exports` drop everything for Mach-O — 4hr — implement (T3 if full impl)
- **F-0346** (cat 16) [core-orchestration] `_extract_imports` for ELF only PLT relocations — 1hr — also DT_NEEDED
- **F-0347** (cat 16) [sandbox-scripts] clipboard_monitor clobbers `$pid` — 15min — rename
- **F-0348** (cat 16) [sandbox-scripts] injection_monitor mislabels normal threads — 2hr — proper heuristic
- **F-0349** (cat 16) [sandbox-scripts] dll_monitor file-mode logman collides with realtime ETW — 1hr — separate sessions
- **F-0350** (cat 16) [sandbox-scripts] dll_monitor brute-force then silent return — 1hr — fail loud
- **F-0351** (cat 16) [sandbox-scripts] dll_monitor catch falls back to WMI silently — 30min — surface

## T2: GUI / UX wiring fixes

- **F-0354** (cat 18) [bridges-cutter-frida] Cutter declares supports_dynamic=False but exposes ESIL — 1hr — fix flag or restrict
- **F-0356** (cat 18) [bridges-x64dbg] `set_breakpoint_on_api` uses `bpx` fails silently — 2hr — resolve via GetProcAddress
- **F-0363** (cat 18) [ui-app-core] HxD toolbar button broken — 30min — wire to add_hxd_tab impl (T3 if HxDPanel needs wiring too)
- **F-0364** (cat 18) [ui-app-core] "Save Patched Binary..." reports no hex editor — 30min — query embedded_tools
- **F-0365** (cat 18) [ui-app-core] Sandbox panel "active widget" wrong dict — 30min — query sandbox dict
- **F-0366** (cat 18) [ui-app-core] XPUStatusDialog never wired — 30min — add menu
- **F-0367** (cat 18) [ui-app-core] FunctionListPanel/XRefPanel never populated — 2hr — wire bridge results
- **F-0368** (cat 18) [ui-app-core] `_on_view_scripts` collects then discards — 30min — pass to dialog
- **F-0369** (cat 18) [ui-app-core] Tool Status prefetch not passed to dialog — 30min — pass
- **F-0370** (cat 18) [ui-app-core] Configure Tools dialog without live registry — 30min — pass
- **F-0371** (cat 18) [ui-app-core] _on_open_sandbox throwaway dialog — 30min — bare check
- **F-0372** (cat 18) [ui-app-core] _apply_provider_settings ignores disabled providers — 30min — disconnect
- **F-0373** (cat 18) [ui-app-core] PreferencesDialog signal no consumer — 30min — wire
- **F-0374** (cat 18) [ui-app-core] SessionManagerDialog signal no consumer — 30min — wire
- **F-0375** (cat 18) [ui-app-core] ProviderConfigDialog signal no consumer — 30min — wire
- **F-0376** (cat 18) [ui-app-core] ModelSelectionDialog signal no consumer — 30min — wire
- **F-0377** (cat 18) [ui-app-core] SandboxConfigDialog signal no consumer — 30min — wire
- **F-0378** (cat 18) [ui-app-core] SandboxMonitorWidget signal no consumer — 30min — wire
- **F-0379** (cat 18) [ui-app-core] ToolConfigDialog signal no consumer — 30min — wire
- **F-0380** (cat 18) [ui-app-core] ToolSettingsWidget signal no consumer — 30min — wire
- **F-0381** (cat 18) [ui-app-core] ToolOutputPanel signals no consumers — 30min — wire
- **F-0382** (cat 18) [ui-panels-hex] search wired to non-existent self._document — 30min — fix attr
- **F-0384** (cat 18) [ui-panels-process] `_status_arch` permanent "Arch: --" — 30min — pull from bridge
- **F-0385** (cat 18) [ui-panels-process] `_status_priv` private bridge attr never refreshed — 30min — pull on refresh
- **F-0386** (cat 18) [ui-panels-process] `_region_filter` filter input never connected — 15min — wire
- **F-0387** (cat 18) [ui-panels-process] `_mod_filter` filter input never connected — 15min — wire
- **F-0388** (cat 18) [ui-panels-process] memory tab actions not gated on attachment — 30min — gate
- **F-0389** (cat 18) [ui-panels-process] `_on_search` "Searching..." never resets on failure — 15min — try/finally
- **F-0390** (cat 18) [ui-panels-process] `_on_free` adds new "Freed" row instead of removing — 30min — remove
- **F-0391** (cat 18) [ui-panels-process] _on_protect/_on_free parse errors logged not surfaced — 30min — message box
- **F-0393** (cat 18) [ui-panels-process] suspend/resume mislabeled — they suspend whole process — 30min — switch to per-thread API
- **F-0394** (cat 18) [ui-panels-process] _on_tls reads TID from Fiber combo — 15min — fix
- **F-0395** (cat 18) [ui-panels-process] thread combos only update on Refresh — 30min — auto-refresh
- **F-0396** (cat 18) [ui-panels-process] _inject_btn no attachment check — 30min — gate + feedback
- **F-0397** (cat 18) [ui-panels-process] `_on_filter_changed` full bridge round-trip per keystroke — 30min — debounce
- **F-0398** (cat 18) [ui-panels-process] `_on_attach` does not surface failure — 15min — message box
- **F-0399** (cat 18) [ui-panels-process] suspend/resume/terminate silently consume errors — 30min — surface
- **F-0400** (cat 18) [ui-panels-process] `_on_terminate` only refreshes system list — 15min — both
- **F-0401** (cat 18) [ui-panels-process] `_on_terminate` doesn't detach if attached — 30min — detach
- **F-0402** (cat 18) [ui-panels-process] `_on_write_registers` reads only Hex column — 30min — also Decimal
- **F-0403** (cat 18) [ui-panels-process] `_on_pipe_close` removes row before knowing close succeeded — 15min — defer
- **F-0404** (cat 18) [ui-panels-process] `_on_job_info` appends instead of clearing — 15min — clear
- **F-0406** (cat 18) [ui-panels-process] SystemTab queries swallow errors silently — 30min — surface
- **F-0407** (cat 18) [ui-panels-process] ModulesTab refreshes swallow errors — 30min — surface
- **F-0409** (cat 18) [ui-panels-process] TrackedRefreshWorker swallows errors — 30min — emit error
- **F-0410** (cat 19) [bridges-cutter-frida] read_memory `data` key collides — 30min — rename
- **F-0411** (cat 19) [bridges-cutter-frida] `_cmd_json` returns silent [] on JSON parse failure — 30min — raise
- **F-0414** (cat 19) [bridges-ghidra] xrefs collapse all types to call/data — 30min — preserve enum
- **F-0415** (cat 19) [bridges-hex] `_build_ips_from_patches` overflow handling broken — 1hr — fix
- **F-0416** (cat 19) [bridges-hex] `_apply_ips_patches` premature break + invented EOF marker — 1hr — fix
- **F-0417** (cat 19) [bridges-hex] UTF-16LE scanner only checks even offsets — 30min — also odd
- **F-0420** (cat 19) [bridges-process] `_extract_env_pointer` bogus offsets / wrong field width — 1hr — fix
- **F-0421** (cat 19) [bridges-process] `_parse_service_entries` stores raw c_wchar_p — 30min — copy strings
- **F-0422** (cat 19) [bridges-process] `_resolve_symbol` magic SizeOfStruct expression — 30min — sizeof
- **F-0423** (cat 19) [bridges-process] `_resolve_module` undersized 584-byte buffer — 30min — proper size
- **F-0424** (cat 19) [bridges-process] `_check_inproc_server` only InprocServer32 — 30min — also LocalServer/InprocHandler
- **F-0425** (cat 19) [bridges-process] get_environment caps env-block at 64 KiB — 30min — read full
- **F-0426** (cat 19) [bridges-process] `_extract_env_pointer` reads <H for EnvironmentSize — 15min — <I
- **F-0428** (cat 19) [bridges-sandbox] `_report_to_dict` emits non-serialisable dataclasses — 1hr — proper to_dict
- **F-0429** (cat 19) [bridges-sandbox] timestamps without timezone labelling in schema — 30min — TZ-aware
- **F-0430** (cat 19) [bridges-x64dbg] `_detect_architecture` returns True on any I/O failure — 1hr — tri-state + raise
- **F-0431** (cat 19) [bridges-x64dbg] `_extract_command_line_from_peb` silently trims odd length — 15min — reject
- **F-0433** (cat 19) [core-hexpat] generic templates parsed but ignored — 4hr — implement (T3 if full)
- **F-0434** (cat 19) [core-hexpat] `using` alias rejects array/pointer/padding — 1hr — accept
- **F-0435** (cat 19) [core-hexpat] namespaced types collide on local name — 1hr — qualify
- **F-0436** (cat 19) [core-hexpat] `_eval_array_field` ignores `is_pointer` — 30min — handle
- **F-0437** (cat 19) [core-hexpat] HexPatCompiler accepts patterns evaluator runs — 1hr — align
- **F-0438** (cat 19) [providers-cloud] `_convert_tool_choice_to_openai_format` empty function name — 30min — validate
- **F-0439** (cat 19) [providers-local] cloud-stream tool-call dict args silently dropped — 30min — handle
- **F-0440** (cat 19) [providers-local] `_extract_text_before_tool_call` regex misses whitespace — 30min — better regex
- **F-0441** (cat 19) [ui-panels-hex] `_scripting._DocAPI.search_text` hardcodes UTF-8 — 30min — read combo
- **F-0442** (cat 19) [ui-panels-hex] `execute_script` `print(file=...)` lost — 30min — handle
- **F-0443** (cat 19) [ui-panels-main] VNCWidget pump silently drops every encoding except RAW — 4hr — implement encodings (T3)
- **F-0352** (cat 17) [bridges-hex] get_context_for_ai returns unbounded bookmark list — 30min — cap
- **F-0353** (cat 17) [bridges-hex] get_digram_matrix 65536 ints per call — 30min — cap or summarise
- **F-0323** (cat 16) [bridges-cutter-frida] save_binary uses wtf — 1hr — switch to wcf
- **F-0325** (cat 16) [bridges-cutter-frida] Frida call_function returns toInt32() truncating 64-bit — 30min — toString().toBigInt
- **F-0326** (cat 16) [bridges-hex] get_pe_imports/exports load full doc — 1hr — chunk
- **F-0330** (cat 16) [bridges-hex] Mach-O missing despite supported_formats — see T5 (full Mach-O)
- **F-0331** (cat 16) [bridges-hex] Mach-O magics return [] silently in auto_detect — 30min — raise pending
- **F-0216** (cat 9) [bridges-hex] fpdf module lazy-import without runtime check — 30min — raise nice error
- **F-0217** (cat 9) [bridges-installer] hardcoded pipe name prevents multi-instance — 1hr — generate per-instance
- **F-0221** (cat 9) [bridges-sandbox] reaches into private QEMU `_qmp`/`_agent` — 1hr — public accessors
- **F-0223** (cat 9) [bridges-x64dbg] evaluate_expression returns 0 for non-string/int — 30min — raise
- **F-0228** (cat 9) [providers-meta] ProviderRegistry not a true factory — 1hr — add ProviderName→class map
- **F-0232** (cat 9) [ui-panels-hex] `_sandbox.py` reimplements docker/qemu/scp logic — 4hr — route through SandboxBridge (T3 in aggregate)
- **F-0209** (cat 9) [bridges-cutter-frida] resolve_symbol fabricates `sub_<addr>` — 30min — return None
- **F-0210** (cat 9) [bridges-cutter-frida] compile_typescript instantiates Compiler per call — 1hr — cache
- **F-0215** (cat 9) [bridges-hex] apply_transform/apply_pipeline never write back — 1hr — write
- **F-0296** (cat 13) [core-orchestration] _validate_tool_schemas only logs warnings — see T1
- **F-0212** (cat 9) [bridges-ghidra] indented multi-line scripts will IndentationError — 2hr — wrap dedent (T3 in aggregate due to 84 sites)
- **F-0500** (cat 21) [sandbox-py] QEMU `apply_anti_evasion` uses reg.exe blocked by allowlist — 1hr — switch to native PowerShell
- **F-0501** (cat 21) [sandbox-py] QEMU `apply_anti_evasion(profile)` ignores profile — 1hr — honour
- **F-0493** (cat 21) [sandbox-py] `_file_monitor_source` uses `$using:` invalid in -Action — 1hr — switch to `$global:` or refactor
- **F-0494** (cat 21) [sandbox-py] QEMU agent script same `$using:` defect — 1hr — fix
- **F-0496** (cat 21) [sandbox-py] `_detect_accelerator` reports WHPX on Hyper-V-disabled — 30min — verify with bcdedit
- **F-0497** (cat 21) [sandbox-py] `_process_monitor_source` uses `$pid` automatic — 30min — rename
- **F-0498** (cat 21) [sandbox-py] `_registry_monitor_source` hardcoded REG_SZ — 30min — handle types

## T2: Sandbox manager / lifecycle

- **F-0301** (cat 11) — see above
- **F-0359** (cat 18) [sandbox-py] `_cleanup` shutil.rmtree silently swallows errors — 30min — log
- **F-0360** (cat 18) [sandbox-py] `get_available_types` triggers expensive subprocesses every call — 30min — cache
- **F-0361** (cat 18) [sandbox-py] stop doesn't clean active captures — 1hr — stop captures first
- **F-0362** (cat 18) [sandbox-py] run_command ticket files never deleted — 30min — cleanup
- **F-0511** (cat 24) [bridges-cutter-frida] generic except Exception swallow Frida transport errors — 2hr — narrow
- **F-0513** (cat 24) [bridges-ghidra] decompile/read_bytes/disassemble silently degrade — 1hr — raise
- **F-0514** (cat 24) [bridges-hex] open_process_memory doesn't close previous doc — 30min — close
- **F-0515** (cat 24) [bridges-installer] `_PIPE_ERROR_HINTS` covers only 3 errors — 30min — expand
- **F-0516** (cat 24) [bridges-installer] deploy_x64dbg_plugin returns True when one arch up-to-date — 30min — gate
- **F-0517** (cat 24) [bridges-installer] _extract_archive returns tool_dir when no subdir — 30min — fail
- **F-0518** (cat 24) [bridges-x64dbg] fallback travels same broken pipe — 1hr — distinguish "no RPC" vs "no pipe"
- **F-0520** (cat 24) [core-analysis] AnalysisAggregator continues with BinaryInfo only — 1hr — raise
- **F-0521** (cat 24) [core-hexpat] parser collects errors but never returns them — 30min — return
- **F-0522** (cat 24) [providers-cloud] `_retry_with_backoff` only Anthropic/OpenAI — 2hr — wire to remaining
- **F-0006** (cat 1) [sandbox-py] `QEMUSandbox.start()` instantiates GuestAgentClient never connect — see T4 (depends F-0007)
- **F-0001** (cat 1) [bridges-ghidra] read_bytes empty due to F-0001 — see F-0253 (T4)
- **F-0009** (cat 1) [sandbox-scripts] api_trace.ps1 starts logman ETL never harvests — 2hr — harvest
- **F-0010** (cat 1) [sandbox-scripts] api_trace handler relies on payload field names provider doesn't expose — 1hr — align
- **F-0011** (cat 1) [sandbox-scripts] api_trace cleanup mixes managed-session disposal — 30min — fix
- **F-0013** (cat 1) [ui-panels-main] SandboxPanel deprecated SandboxBase setters — 30min — remove
- **F-0026** (cat 2) [core-hexpat] `_mem_base_address` hardwires 0 — see T1
- **F-0148** (cat 6) [bridges-cutter-frida] detached scripts left in mappings when unload raises — 30min — guarded cleanup
- **F-0147** (cat 6) [bridges-cutter-frida] enable_crash_reporting unbounded callback — 30min — idempotent
- **F-0265** (cat 9) — see above
- **F-0250** (cat 8) — see T1
- **F-0467** (cat 18) — see above
- **F-0007** (cat 1) [sandbox-py] no mechanism to start guest agent script — see T4 (combined w/ F-0006 for T5)
- **F-0007** (cat 4) [sandbox-py] extract_dropped_files won't work if agent disconnected — 1hr — proper error
- **F-0081** (cat 4) [sandbox-py] extract_dropped_files allowlist mismatch — see above (F-0007 sandbox-py)
- **F-0082** (cat 4) [sandbox-py] pktmon writes ETL not PCAP — 2hr — convert
- **F-0083** (cat 4) [sandbox-py] apply_anti_evasion patches volatile registry — 2hr — write to user hive
- **F-0300** (cat 13) [sandbox-py] Windows run_binary 3-second sleep — 1hr — proper wait
- **F-0301** (cat 13) [sandbox-py] QEMU run_binary 2-second sleep — 1hr — proper wait
- **F-0299** (cat 13) [sandbox-py] `_resolve_worker_pid` heuristic doesn't match docstring — 30min — fix doc or impl
- **F-0029** (cat 3) [bridges-x64dbg] step-execution functions sleep 50ms — 1hr — wait on event
- **F-0181** (cat 7) [bridges-ghidra] `_wait_for_bridge_port` polls but never drains stderr — 1hr — drain in thread

## T2: Other

- **F-0042** (cat 4) — see T1
- **F-0038** (cat 4) [bridges-hex] DIE scanner is fundamental loss of capability — 4hr — proper signature engine (T3)
- **F-0039** (cat 4) [bridges-hex] read_bytes registered as LLM tool with no length cap — 30min — cap
- **F-0041** (cat 4) [bridges-hex] BPS encoder degenerate; only emits SourceRead/TargetRead — 4hr — implement SourceCopy/TargetCopy (T3)
- **F-0036** (cat 4) [bridges-ghidra] get_call_graph walks every address per byte — 4hr — getReferencesFromAddressSet (T3)
- **F-0223** (cat 7) — see T1
- **F-0224** (cat 7) — see T1
- **F-0010** (cat 4) [bridges-installer] send_command increments id outside lock — see T1
- **F-0050** (cat 4) — see T1
- **F-0187** (cat 7) [bridges-installer] sync event_handler called inside I/O lock — 1hr — release lock
- **F-0188** (cat 7) [bridges-installer] single global lock serialises all pipe commands — 2hr — split locks
- **F-0282** — see above

---

# T3 — Medium (90 findings)

Multi-method or multi-file refactor, cross-module integration. 4 hours – 1 day.

- **F-0281** (cat 13) [bridges-ghidra] `set_label`/`add_comment`/`rename_function`/`create_bookmark`/etc verify success — 8hr — verify each via remote_eval (8 methods)
- **F-0216** (cat 9) [bridges-hex] fpdf module lazy-import — see T2
- **F-0227** (cat 9) [core-orchestration] Cutter bridge never auto-initialized — see T2
- **F-0432** (cat 19) [core-hexpat] variadic params parsed but ignored at call — 4hr — implement variadic binding
- **F-0488** (cat 21) [core-hexpat] missing `builtin::std::mem::*` callees — 8hr — register + implement (read_bits, find_string_in_range, sections etc.)
- **F-0435** (cat 19) [core-hexpat] namespaced types collide on local name — see T2 (T3 if rename refactor needed)
- **F-0437** (cat 19) [core-hexpat] HexPatCompiler accepts patterns evaluator runs but compiler doesn't — 4hr — align surfaces
- **F-0021** (cat 2) [bridges-x64dbg] Many wrappers return hardcoded success — 16hr aggregate — verify each (per-method T2 = 30min × 20)
- **F-0212** (cat 9) [bridges-ghidra] indented inline scripts IndentationError — 4hr — bulk dedent
- **F-0232** (cat 9) [ui-panels-hex] `_sandbox.py` reimplements docker/qemu/scp — 8hr — route through bridge
- **F-0443** (cat 19) [ui-panels-main] VNCWidget drops every encoding except RAW — 8hr — Hextile/CopyRect/ZRLE
- **F-0517** (cat 19) — same as above
- **F-0222** (cat 9) [bridges-x64dbg] most public methods unconditionally call pipe; no script fallback — 16hr — script-command fallback for every public method (T4 in aggregate)
- **F-0131** (cat 5) [bridges-x64dbg] bare except Exception swallow paths — see T2
- **F-0010** (cat 4) [bridges-hex] ClamAV NDB scanner strips wildcards — 8hr — wildcard FSM
- **F-0011** (cat 4) [bridges-hex] DIE scanner fundamental loss — 16hr — DIE-format engine (T4 if full DIE script eval)
- **F-0028** (cat 4) [bridges-hex] BPS encoder degenerate — 8hr — full BPS spec
- **F-0007** (cat 4) [bridges-hex] `_build_ips_from_patches` overflow — see T2
- **F-0011** (cat 4) [bridges-ghidra] get_call_graph walks per byte — 4hr — single getReferencesFromAddressSet
- **F-0166** (cat 6) [bridges-process] shutdown doesn't unmap sections — see T2
- **F-0220** (cat 7) — see T1 (T2 if redesign locking)
- **F-0188** (cat 7) [bridges-installer] single global lock serialises pipe commands — see T2
- **F-0336** (cat 16) [bridges-process] inject_dll discards WaitForSingleObject return; UTF-8 path — see T2
- **F-0338** (cat 16) [bridges-process] get_handles returns raw ObjectTypeIndex — see T2
- **F-0340** (cat 16) [bridges-process] get_tls_values reads from expansion slot — see T2
- **F-0346** (cat 16) [core-orchestration] `_extract_imports` ELF only PLT — 4hr — full DT_NEEDED
- **F-0348** (cat 16) [sandbox-scripts] injection_monitor mislabels normal threads — 4hr — proper APC + remote-thread fingerprinting
- **F-0517** — already listed
- **F-0366** (cat 18) [ui-app-core] XPUStatusDialog never wired — see T2
- **F-0367** (cat 18) [ui-app-core] FunctionListPanel/XRefPanel never populated — 4hr — wire bridge data
- **F-0274** — already listed
- **F-0441** — already
- **F-0416** (cat 19) [bridges-hex] `_apply_ips_patches` premature break + invented EOF marker — see T2
- **F-0415** (cat 19) [bridges-hex] `_build_ips_from_patches` overflow — see T2
- **F-0426** (cat 19) [bridges-process] `_extract_env_pointer` reads <H — see T1
- **F-0428** (cat 19) [bridges-sandbox] `_report_to_dict` non-serialisable dataclasses — see T2
- **F-0434** (cat 19) [core-hexpat] `using` alias rejects array/pointer/padding — see T2 (T3 if requires AST refactor)
- **F-0436** (cat 19) [core-hexpat] `_eval_array_field` ignores `is_pointer` — see T2
- **F-0433** (cat 19) [core-hexpat] generic templates parsed but ignored — 8hr — implement template evaluation
- **F-0511** — already
- **F-0438** (cat 19) [providers-cloud] _convert_tool_choice empty function name — see T2
- **F-0370** (cat 18) [ui-app-core] Configure Tools dialog without live registry — see T2 (T3 if dialog needs major rework)
- **F-0354** (cat 18) [bridges-cutter-frida] supports_dynamic=False but exposes ESIL — see T2
- **F-0356** (cat 18) [bridges-x64dbg] set_breakpoint_on_api uses bpx fails silently — 4hr — resolve via NtQueryInformation + GetProcAddress fallback
- **F-0393** (cat 18) [ui-panels-process] suspend/resume mislabeled — suspend whole process — see T2
- **F-0274** — already
- **F-0517** — already
- **F-0022** (cat 2) [bridges-x64dbg] set_breakpoint synthetic local id — 4hr — return native id from plugin (requires plugin RPC change too)
- **F-0023** (cat 2) [bridges-x64dbg] patch_anti_debug only patches two checks — 8hr — expand to dozens of common checks
- **F-0026** (cat 2) [core-hexpat] `_mem_base_address` hardwires 0 — see T1 (T2-T3 if pragma plumbing)
- **F-0027** (cat 2) [core-hexpat] `_core_array_index` always 0 — see T1
- **F-0031** (cat 4) [bridges-cutter-frida] `get_function_address` enumerates all then filters — see T2
- **F-0098** (cat 5) [bridges-cutter-frida] allocate_memory loop doesn't break — see T2
- **F-0149** (cat 6) [bridges-ghidra] shutdown doesn't close ghidra_bridge RPC client — see T2
- **F-0150** (cat 6) [bridges-ghidra] shutdown deletes bridge script without serialising — see T2
- **F-0190** (cat 7) [bridges-process] async methods loop tens of thousands times — see T2
- **F-0191** (cat 7) [bridges-x64dbg] `_breakpoints`/`_watchpoints` mutated from threads without lock — see T2
- **F-0193** (cat 7) [core-orchestration] SessionManager.update blocking SQLite — see T2
- **F-0209** (cat 9) [bridges-cutter-frida] resolve_symbol fabricates sub_<addr> — see T2
- **F-0210** (cat 9) [bridges-cutter-frida] compile_typescript instantiates Compiler per call — see T2
- **F-0217** (cat 9) [bridges-installer] hardcoded pipe name — see T2
- **F-0218** (cat 9) [bridges-installer] `_open_handle` share_mode=0 — see T2
- **F-0219** (cat 9) [bridges-installer] deploy_x64dbg_plugin Program Files write — see T2
- **F-0220** (cat 9) [bridges-installer] cmake/build feedback dropped — see T2
- **F-0221** (cat 9) [bridges-sandbox] reaches into private QEMU attributes — see T2
- **F-0223** (cat 9) [bridges-x64dbg] evaluate_expression returns 0 ambiguous — see T2
- **F-0228** (cat 9) [providers-meta] ProviderRegistry not factory — see T2
- **F-0229** (cat 9) [sandbox-scripts] start_monitors fire-and-forget — see T2
- **F-0230** (cat 9) [ui-panels-hex] highlight rules update only local widget — see T2
- **F-0231** (cat 9) [ui-panels-hex] `_process_memory.py` bypasses bridge — see T2
- **F-0233** (cat 9) [ui-panels-hex] IPS/BPS/UPS export+import bypass — see T2
- **F-0234** (cat 9) [ui-panels-hex] `_data_inspector._on_encode_text` falls back to class encoder — see T2
- **F-0246** (cat 11) [bridges-sandbox] BridgeState wired once never updated — see T2
- **F-0249** (cat 11) [core-orchestration] User message persists when agent loop fails — see T2
- **F-0255** (cat 11) [providers-meta] DiscoveryCache load_from_disk partially overwrites — see T2
- **F-0259** (cat 11) [ui-panels-hex] document mutations skip notify_data_modified in 5+ mixins — see T2
- **F-0262** (cat 11) [ui-panels-hex] pattern editor and templates partial sync — see T2
- **F-0265** (cat 12) [bridges-hex] set_display_mode/set_color_mode don't validate — see T1
- **F-0266** (cat 12) [core-hexpat] std::core::set_endian doesn't affect struct reads — see T2
- **F-0271** (cat 12) [providers-cloud] enable_cache discarded — see T1 (T2-T3 if wiring SDK)
- **F-0272** (cat 12) [providers-cloud] thinking discarded — see T1 (T2-T3 if wiring)
- **F-0281** (cat 13) [bridges-ghidra] verify success on 8 methods — see top of T3
- **F-0306** (cat 14) [bridges-ghidra] import_debug_info no canonicalisation — see T2
- **F-0307** (cat 14) [bridges-hex] run_python_script sandbox escapable (RCE) — 8hr — proper RestrictedPython or subprocess (T4 if full subprocess sandbox)
- **F-0335** (cat 16) [bridges-process] thread_context picks 64/32 by host pointer ignoring WOW64 — see T2
- **F-0338** (cat 16) [bridges-process] get_handles returns raw ObjectTypeIndex — see T2
- **F-0342** (cat 16) [bridges-x64dbg] get_resources only walks top level — see T2
- **F-0345** (cat 16) [core-orchestration] `_extract_imports`/`_extract_exports` drop everything for Mach-O — 8hr — implement Mach-O traversal
- **F-0348** (cat 16) [sandbox-scripts] injection_monitor mislabels — see T2 (T3 for proper heuristic)
- **F-0349** (cat 16) [sandbox-scripts] dll_monitor file-mode/realtime collision — see T2
- **F-0068** (cat 4) [core-orchestration] naive token estimate — see T1 (T2 if proper tokenizer per provider)
- **F-0070** (cat 4) [core-orchestration] missing context window disables trimming — see T2
- **F-0077** (cat 4) [providers-meta] DiscoveryFilter pattern.match start-anchored — see T1
- **F-0091** (cat 4) [ui-app-core] ProviderSettingsWidget only wires three providers — see T2
- **F-0092** (cat 4) [ui-app-core] _on_browse_models_result without provider context — see T2
- **F-0006** (cat 9) [bridges-hex] apply_transform/apply_pipeline never write back — see T2 (T3 if API redesign needed)
- **F-0083** (cat 4) [sandbox-py] apply_anti_evasion volatile hive — see T2 (T3 if redesign)
- **F-0340** (cat 16) [bridges-process] get_tls_values expansion slot — see T2
- **F-0338** (cat 16) [bridges-process] get_handles raw type indices — see T2
- **F-0009** (cat 1) [sandbox-scripts] api_trace logman ETL never harvested — see T2 (T3 if rebuild capture-flush)
- **F-0010** (cat 1) [sandbox-scripts] api_trace handler payload field name mismatch — see T2

---

# T4 — Large (45 findings)

Whole-bridge refactor, asyncio redesign, multi-day work. 1–3 days each.

- **F-0211** (cat 9) [bridges-ghidra] every `_execute_remote` call broken — `remote_exec` discards trailing expression — **2-3 days** — switch entire bridge to `remote_eval` for value-returning scripts; audit all 84 call sites; refactor inline scripts into module constants
- **F-0212** (cat 9) [bridges-ghidra] indented multi-line scripts IndentationError — **1 day** — bulk dedent + audit (linked to F-0253)
- **F-0213** (cat 9) [bridges-ghidra] `start_headless` calls non-existent constructor — **1 day** — switch to `GhidraBridgeServer.run_server`
- **F-0214** (cat 9) [bridges-ghidra] `analyzeHeadless -postScript` doesn't keep JVM alive — **1-2 days** — proper headless launcher arrangement
- **F-0021** (cat 2) [bridges-x64dbg] all wrappers fake-success in aggregate — **2-3 days** — verify each via post-condition; depends on plugin RPC redesign
- **F-0222** (cat 9) [bridges-x64dbg] most public methods no script-command fallback — **3 days** — implement script fallback for every public method missing one
- **F-0001** (cat 1) [bridges-ghidra] read_bytes etc empty due to F-0001 — folded into F-0253
- **F-0019** (cat 13) [bridges-hex] wholesale change event after every modification — **1-2 days** — emit fine-grained ranges from Rust + propagate
- **F-0100** (cat 5) [bridges-ghidra] functions swallow exceptions return empty defaults — **2 days** — distinguish "no data" from "ghidra error" across ~30 read methods
- **F-0130** (cat 5) [bridges-x64dbg] `_is_recoverable_pipe_error` substring matching — **1-2 days** — typed errors from plugin RPC + bridge decode
- **F-0007** (cat 4) [sandbox-py] no mechanism to start guest agent script — **2-3 days** — autorun via Sysprep/RunOnce or ETW-driven dispatcher
- **F-0006** (cat 1) [sandbox-py] `QEMUSandbox.start()` instantiates GuestAgentClient never connect — **1-2 days** — connect, retry, plumb through start
- **F-0201** (cat 7) [sandbox-py] `SandboxManager.create()` deadlocks on capacity eviction — **1 day** — re-entrant lock or release-then-reacquire
- **F-0232** (cat 9) [ui-panels-hex] `_sandbox.py` reimplements docker/qemu/scp — **1 day** — full route through SandboxBridge with snapshotting
- **F-0443** (cat 19) [ui-panels-main] VNCWidget framebuffer pump RAW only — **1-2 days** — implement Hextile/CopyRect/ZRLE/Tight encodings
- **F-0348** (cat 16) [sandbox-scripts] injection_monitor heuristic wrong — **1-2 days** — proper APC/remote-thread/manualmap detector
- **F-0038** (cat 4) [bridges-hex] DIE scanner fundamental loss — **2 days** — implement DIE script subset evaluator
- **F-0011** (cat 1) [core-hexpat] missing `builtin::std::mem::*` callees — **1-2 days** — register + implement read_bits/find_string_in_range/sections (depends on F-0266 namespace fix first)
- **F-0006** (cat 5) [core-hexpat] reflection provider hooks raise on every call — **1 day** — implement provider end-to-end (HexEditorBridge supplies metadata)
- **F-0008** (cat 12) [core-hexpat] `std::core::set_endian` doesn't affect struct reads — **1 day** — wire stdlib state into evaluator
- **F-0017** (cat 19) [core-hexpat] `_eval_array_field` ignores `is_pointer` — see T2 (T4 only if AST refactor)
- **F-0008** (cat 19) [bridges-hex] `_apply_ips_patches` premature break + invented EOF marker — see T2 (T4 if must rewrite to spec from scratch)
- **F-0223** (cat 9) [bridges-x64dbg] evaluate_expression returns 0 — see T2
- **F-0023** — already
- **F-0281** (cat 13) [bridges-ghidra] `set_label`/`add_comment`/etc verify — see T3
- **F-0306** (cat 14) [bridges-ghidra] import_debug_info no canonicalisation — see T2
- **F-0307** (cat 14) [bridges-hex] run_python_script sandbox escapable — **1-2 days** — switch to subprocess sandbox with seccomp/job objects
- **F-0024** (cat 9) [bridges-installer] cmake/build feedback dropped — see T2
- **F-0228** (cat 9) [providers-meta] ProviderRegistry not factory — see T2
- **F-0071** (cat 4) [providers-cloud] Anthropic enable_cache only system prompt — see T2 (T3 in real impl)
- **F-0433** (cat 19) [core-hexpat] generic templates parsed but ignored — **1-2 days** — implement template evaluation in evaluator
- **F-0009** (cat 1) [sandbox-scripts] api_trace logman ETL never harvested — see T3
- **F-0407** — already
- **F-0083** (cat 4) [sandbox-py] apply_anti_evasion volatile hive — see T3
- **F-0338** (cat 16) [bridges-process] get_handles raw ObjectTypeIndex — see T2 (T3-T4 if NtQueryObject loop)
- **F-0349** (cat 16) [sandbox-scripts] dll_monitor session collision — see T2 (T3 if dual-session refactor)
- **F-0336** (cat 16) [bridges-process] inject_dll — see T2 (T3-T4 if proper LoadLibraryW + GetExitCodeThread + handshake)
- **F-0335** (cat 16) [bridges-process] thread_context WOW64 — see T2 (T3-T4 if Wow64GetThreadContext + cross-arch ToContext64 conversions)
- **F-0062** (cat 4) [bridges-x64dbg] find_pattern wildcards reads only 1 MiB — see T2 (T3 if wildcard streaming)
- **F-0064** (cat 4) [bridges-x64dbg] `_read_module_entry_point` returns 0 silent — see T2 (T3-T4 if proper PE32/PE32+)
- **F-0221** (cat 9) [bridges-sandbox] reaches into private QEMU attrs — see T2 (T3 if creating proper public surface)
- **F-0246** (cat 11) [bridges-sandbox] BridgeState frozen — see T2 (T3 if event subscription)
- **F-0011** (cat 4) [bridges-ghidra] get_call_graph per-byte — see T3 (T4 if needs Symbolic + Reference services overhaul)
- **F-0022** (cat 2) [bridges-x64dbg] set_breakpoint synthetic id — see T3 (T4 if plugin RPC + caller refactor)
- **F-0023** (cat 2) [bridges-x64dbg] patch_anti_debug only patches two — see T3
- **F-0021** — already
- **F-0395** — already
- **F-0188** (cat 7) [bridges-installer] single global lock — see T2 (T3-T4 if true full-duplex pipe)
- **F-0264** — already
- **F-0254** — already

---

# T5 — Epic (15 findings)

Multi-week subsystem rewrite or genuinely difficult work. 1+ weeks each.

- **F-0224** (cat 9) [core-hexpat] `builtin::*` namespace path is unreachable; entire std-lib namespace evaluation broken — **1-2 weeks** — implement proper namespace AST resolution + 100+ keys; cascade-fix F-0488, F-0011, F-0491, F-0005, F-0025
- **F-0491** (cat 21) [core-hexpat] `_eval_namespace_access` synthesises wrong qualified names for multi-segment paths — **bundled with F-0224**
- **F-0226** (cat 9) [core-hexpat] interpreter.execute() never connects evaluator/state to stdlib — **1 week** — wire endian/print sink/reflection provider/array-index propagation throughout interpreter
- **F-0330** (cat 16) [bridges-hex] Mach-O missing despite supported_formats — **1-2 weeks** — implement Mach-O LC_LOAD_DYLIB, LC_SYMTAB, LC_REEXPORT_DYLIB, FAT/Universal binary handling
- **F-0010** (cat 4) [bridges-hex] ClamAV NDB scanner strips wildcards — **1-2 weeks** — full NDB+LDB+CDB+MDB+FP+IGN signature engine (Hyperscan or custom NFA)
- **F-0011** (cat 4) [bridges-hex] DIE scanner fundamental loss — **1-2 weeks** — DIE script language subset evaluator (Detect-It-Easy uses JavaScript-like DSL)
- **F-0028** (cat 4) [bridges-hex] BPS encoder degenerate — **1 week** — implement SourceCopy/TargetCopy/SourceRead/TargetRead per BPS spec for real space savings
- **F-0201** (cat 7) [sandbox-py] SandboxManager deadlock — see T4 (T5 only if requires full async architecture redesign)
- **F-0007** (cat 1) [sandbox-py] no mechanism to start guest agent — **1-2 weeks** — implement guest enrollment, autorun, signed agent payload, transport selection (vsock vs virtio-serial vs SMB)
- **F-0006** (cat 1) [sandbox-py] QEMU GuestAgentClient never connect — bundled with F-0007
- **F-0499** (cat 21) [sandbox-py] `dump_memory` cannot succeed against vmwp.exe — **1 week** — switch to LiveKD or Hyper-V WMI ApplyChanges API; vmwp is PPL
- **F-0323** (cat 16) [bridges-cutter-frida] save_binary uses `wtf` — see T2 (T3 if `wcf` requires re-architect)
- **F-0211** — see T4 (T5 if this is treated as full Ghidra bridge rewrite)
- **F-0222** — see T4 (T5 if full plugin RPC redesign)
- **F-0348** — see T4 (T5 if proper ETW-based detector + signed-driver fingerprinting)

---

# TBD — Investigation needed (4 findings)

Cannot estimate without an architectural/scope decision from the user.

- **F-0232** (cat 9) [ui-panels-hex] `_sandbox.py` route through SandboxBridge — **TBD** — depends on whether SandboxBridge will absorb docker / qemu / scp transport heuristics or whether docker is being deprecated (CHANGELOG mentioned Docker migration)
- **F-0441** (cat 19) [ui-panels-hex] scripting search_text hardcodes UTF-8 ignoring panel encoding combo — **TBD** — depends on whether scripting API should mirror panel state or be programmatic; if programmatic, fix is "remove combo dependency"
- **F-0071** (cat 4) [providers-cloud] Anthropic enable_cache only system prompt — **TBD** — Anthropic charges for cache reads; user must pick whether to cache tools (worth ~$0.30/M input cached) and messages (only worth it if last assistant turn is reused)
- **F-0022** (cat 2) [bridges-x64dbg] set_breakpoint synthetic id — **TBD** — depends on whether the C++ plugin RPC contract can be modified or is a fixed external interface

---

# Cross-tier dependencies

These chains require resolution in order:

1. **Ghidra bridge (Cat 9)**: F-0211 (eval vs exec) → F-0212 (dedent) → F-0001/F-0005/F-0100 (consumers) → F-0281 (verify success). Resolving F-0211 alone makes ~30 read methods start returning real data.

2. **HexPat (Cat 9/19/21)**: F-0224 (namespace path) → F-0488/F-0491/F-0005/F-0025 (std-lib registrations) → F-0226 (interpreter wiring). Without F-0224, every std-lib `.pat` file in `vendor/ImHex-Patterns/` cannot execute.

3. **Sandbox-py guest (Cat 1)**: F-0007 (start agent) → F-0006 (connect agent) → F-0080/F-0084/F-0089/F-0090 (run/extract). Until F-0007/F-0006 land, every QEMU operation is a no-op.

4. **x64dbg plugin RPC (Cat 2/9/13)**: F-0222 (plugin missing fallback) blocks F-0021 (per-method verify), F-0022 (native bp id), F-0130 (typed errors), F-0290 (honest logs). Either plugin becomes hard prerequisite or every public method needs a script fallback.

5. **Hex bridge sandbox escape (Cat 14)**: F-0307 should land before any non-trivial use of `run_python_script` is exposed to LLMs.

6. **Sandbox bridge state (Cat 11)**: F-0246 (BridgeState never updated) gates UI panel correctness around sandbox lifecycle (F-0264, F-0235).

---

# Notes on reliability of estimates

- **T1 estimates** are highly reliable — these are mechanical fixes.
- **T2 estimates** are reliable for the fix itself; add 50-100% for caller audit if blast radius is wide.
- **T3 estimates** depend on whether the necessary infrastructure already exists; if it doesn't, T3 → T4.
- **T4/T5 estimates** are best-case-with-no-surprises; sandbox/x64dbg work in particular often discovers cascading issues during implementation.
- "**Aggregate**" notes (e.g. "T2 per method, T4 in aggregate" for x64dbg wrappers) reflect that the 30 minute fix is a small drop; the bridge has 20 such wrappers, so the total spend is multi-day.

# Recommended sequencing

If tackling subsystem-by-subsystem (best for context preservation):

1. **Quick wins** (~1 week): All T1 findings — measurable churn, low risk, large ratio of progress to effort.
2. **Wiring sweep** (~1 week): T2 GUI/UX (F-0437–F-0483) — restores user-facing functionality for negligible code.
3. **Bridge truthfulness** (~2 weeks): T2/T3 fake-success and error-handling (F-0023, F-0109, F-0139, F-0334) — turns observability from theatre into reality.
4. **Ghidra rewrite** (~1 week): T4 cluster around F-0253.
5. **HexPat std-lib** (~1-2 weeks): T5 cluster around F-0266 + cascading T2/T3.
6. **x64dbg plugin/script split** (~2-3 weeks): T4/T5 cluster around F-0264.
7. **Sandbox guest agent** (~2-3 weeks): T5 cluster around F-0007/F-0006.
8. **Format engines** (~3-4 weeks): T5 ClamAV (F-0010), DIE (F-0011), BPS (F-0030), Mach-O (F-0389) — each a discrete spec implementation.
9. **Long tail**: remaining T2/T3 findings spread across owners.

Total realistic delivery window with one senior engineer: **~6 months**. With three engineers in parallel and good ownership splits: **~3 months** for the bulk, with the format-engine T5 work being the rate-limiter.
