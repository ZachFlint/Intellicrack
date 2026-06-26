# Intellicrack Test-Infrastructure Audit — Master Report

**Audit date:** 2026-06-26
**Method:** 15 parallel adversarial `test-reviewer` agents, one per source section. Each enumerated every behavior-bearing operation in its scope, mapped it to tests across the entire `tests/` tree, and classified each gate as REAL / WEAK / FAKE / NO COVERAGE. A gate is REAL only if a concrete wrong implementation (a named mutation) would turn it red. "It passes" was never accepted as proof.
**Scope:** audit-only. No `src/` or `tests/` file was modified.
**Per-section detail:** `audit/test-coverage-audit/section-NN-*.md`.

---

## 1. Project Scorecard

Gate coverage = (operations with >=1 real falsifiable gate) / (total behavior-bearing operations). Edge-case score is each agent's domain-specific edge coverage.

| # | Section | Gate coverage | Edge-case | Verdict |
|---|---------|:---:|:---:|---|
| 1 | Bridge Framework & IPC | 83% (133/160) | 60% | Below floor — IPC error branches untested |
| 2 | Disassembler / RE-Tool Bridges | 51% (96/187) | ~45% | **FAIL** — Ghidra 31%, Cutter 64%, disasm 100% |
| 3 | Debugger & Instrumentation Bridges | ~38% (X64Dbg 43% / Frida 32%) | ~23% | **WORST SECTION** |
| 4 | PE / Binary-Format & Process Bridges | 75% (104/139) | 55% | Below floor — struct layout & security gaps |
| 5 | Hex-Editor Bridge & State | 93% (137/148) | 62% | Strong — 6 bridge methods uncovered |
| 6 | HexPat Pattern-Language Engine | 93% (211/226) | 58% | Strong — gold-standard dual-oracle suite |
| 7 | Core Orchestration, Session & Context | 88% (105/120) | 65% | **STRONGEST** — zero anti-patterns |
| 8 | Core Infrastructure & Codegen | 89% (116/131) | 78% | Strong — elevation test mocks SUT |
| 9 | Cloud AI Providers | 54% (~76/140) | 70% | Below floor — OpenAI 29%, Ollama 35% |
| 10 | Local AI Models & GPU/Accel | 63% (68/108) | 48% | **FAIL** |
| 11 | Credentials & OAuth | 43% (54/127) | 22% | **FAIL** — OAuth decision tree untested |
| 12 | Sandbox Orchestration & Monitors | ~88% (qualitative) | ~80% | Strong — 1 critical mock file |
| 13 | Rust hexcore Engine | 61% (54/89) | 50% | Below floor — 2 critical zero-cov modules |
| 14 | UI App Shell, Config & Chat | 85% (88/103) | 58% | At floor — 2 zero-cov modules |
| 15 | UI Panels | 82% (145/170) | 89% (8/9) | Below floor (disqualified tests) |

**Weighted project gate coverage ≈ 73%** (≈1,720 real gates over ≈2,375 inventoried operations).
**Sections at/above the 85% floor: 5 of 15** (5, 6, 7, 8, 12). **Sections failing hard (<65%): 5** (2, 3, 9*, 10, 11). (*Section 9 offline-only; live paths are intentionally skipped.)

### Risk tiers

- **Tier 1 — Critical (lowest coverage, highest blast radius):** §3 Debugger bridges, §11 Credentials/OAuth, §2 Disassembler bridges (Ghidra), §10 Local AI models, §13 Rust `data_source.rs`/`templates/eval.rs`.
- **Tier 2 — Below floor, contained:** §1 IPC error paths, §4 win32 struct layouts + security guards, §9 OpenAI/Ollama offline, §14 highlighter/screen_compat, §15 disqualified UI tests.
- **Tier 3 — Strong, finish the tail:** §5, §6, §7, §8, §12.

---

## 2. Forbidden Anti-Patterns Found (must-fix — violate project test rules)

These tests use `unittest.mock` / `MagicMock` / `patch` against the code under test, or inline lint suppression. They are non-gating and several are explicit rule violations.

| ID | File:line | Problem | Mutation that survives |
|----|-----------|---------|------------------------|
| MV-1 | `tests/test_core/test_elevation.py` (throughout) | `patch("...elevation._relaunch_elevated")` — mocks the decision dependency of `maybe_elevate` | Any `maybe_elevate` body that calls the mock passes; decline/retry/arg-selection ungated |
| MV-2 | `tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:257` | `mock.patch(...HexPatCompiler.compile, side_effect=...)` — mocks the compiler it claims to verify | `compile_to_json` error-propagation never runs the real compiler |
| MV-3 | `tests/test_bridges/test_sandbox_bridge.py:17+` | `AsyncMock` on `start_pcap_capture`, `qmp.cont`, snapshot/screenshot ops | Deleting the real pcap/QMP/snapshot bodies leaves tests green |
| MV-4 | `tests/test_providers/test_providers_cloud_audit1.py:377-487` | `MagicMock` client + no transform assertion (`enable_cache` "full call path", OpenAI/Grok/Google) | Forwarding, dropping, or ignoring `enable_cache` all pass |
| MV-5 | `tests/test_bridges/test_process_audit7.py:342,400` | `patch` on `asyncio.to_thread` (forbidden mechanism even as spy) | Rule violation; first test redundant with ticker test |
| MV-6 | `tests/test_audit4/c16_hex_panel_selection_dispatch/test_selection_dispatch.py` | `MagicMock`/`patch` in `TestDocumentOpenedDispatch` + `TestCopyAsClipboardError` | Document-opened + clipboard paths ungated (6 sibling selection tests are clean) |
| MV-7 | `tests/test_audit4/c12_hex_sandbox_route/test_sandbox_route.py` | `# noqa: RUF029` inline suppression on 3 `_inner()` funcs | Inline suppression is prohibited project-wide |

---

## 3. Worst Fake / Weak Gates (passes regardless of correctness)

Beyond the forbidden-mock list, these assert nothing that bites.

| ID | File:line | Bogus assertion | Why it's fake |
|----|-----------|-----------------|---------------|
| FG-1 | `test_x64dbg_audit6.py:832-849` (`read_peb`) | substring `"address"` in the `returns` docstring | Returning `{}` from `read_peb()` passes |
| FG-2 | `test_x64dbg_api_coverage.py:91-116` (breakpoints) | manually inserts `BreakpointInfo` then "finds" it | Tautology — never exercises the `bp_list` RPC |
| FG-3 | `test_x64dbg_api_coverage.py:133-143` (`get_registers`) | only no-plugin `ToolError` path | Zeroed `RegisterState` after success passes |
| FG-4 | `test_ghidra.py` (`TestMutatingMethodsRequireConnection` etc.) | `pytest.raises(ToolError, match="not connected")` on 56 methods | Method body after the guard is fully ungated — `get_functions()->[]` passes |
| FG-5 | `test_realcov_03a_frida_modules.py:169-177,235-246` | bare `pytest.raises(ToolError)`, no `match=` | Any `ToolError` from any source satisfies |
| FG-6 | `test_hex_editor_top_audit1.py:485` (`get_pe_imports`) | `assert isinstance(result, list)` ×3 | `[]` on every call passes |
| FG-7 | `test_bridge_ai_context.py:77,112,51` | `isinstance(bookmarks,list)`, `size>0`, key-existence | Wrong/empty AI context passes |
| FG-8 | `test_data_inspector.py:42-143` (`TestInspectAtBasic`, 11 tests) | `"uint8" in result` + `isinstance(str)` | `{"uint8":"WRONG",...}` passes all 11 |
| FG-9 | `test_openrouter_provider.py:311-326` | `try/except AuthenticationError: pass`, no assertion | Cannot fail under any condition |
| FG-10 | `test_*_provider.py` `test_disconnect_clears_connection_state` (Google/Grok/OpenRouter/Ollama) | `pytest.skip` when no key, then only `is_connected is False` | Always skipped offline; no teardown verified |
| FG-11 | `test_local_xpu_e2e.py` (2-turn / 3-turn / max-tokens) | `assert len(response.content) > 0` | A single space passes |
| FG-12 | `test_local_transformers_provider.py` (`test_list_models_has_recommended_models`) | `any("phi"/"tiny" in m)` | Drops 5 of 7 recommended models silently |
| FG-13 | `test_sandbox_panel_fixes.py` (8 tests) | `combo.count()==2`, `_selected_sandbox_type()=="windows"` | Replacing method with `return "windows"` passes all |
| FG-14 | `test_xpu_status.py:122-232` (9 tests) | widget existence/type only | Wrong `_refresh_device_info()` data passes |
| FG-15 | `test_schemas.py:701-710` (`get_schema_for_provider`) | `len(result)==1` for 5 providers | Routing HUGGINGFACE→anthropic format passes |
| FG-16 | `test_compiler.py` (`test_compile_round_trips_through_shared_lexer`) | `any(isinstance(t,...))` | Deleting keyword dispatch passes |
| FG-17 | `test_process_bridge.py` (`*_no_crash`, `*_returns_dict/list/bool`) | type/existence only on `get_windows`, `get_seh_chain`, `get_fiber_data`, `get_tls_values`, `detect_kernel_debugger`, `get_job_info` | Empty/structurally-wrong results pass |
| FG-18 | `test_cutter.py` (`TestReadBytes`, `TestHexdump`) | `isinstance(result, bytes/str)` | `b"deadbeef"` / `""` passes |

---

## 4. Consolidated Untested-Operation List (zero real coverage)

### Security- and correctness-critical (fix first)
- **OAuth decision tree** (§11): `OAuthToken.is_expired`/`needs_refresh`, `to_dict`/`from_dict`, `OAuthManager.get_token`, `handle_callback` (unknown/expired state, missing PKCE), `OAuthState.is_expired`, `revoke_token`, refresh 403 path, `CredentialStore.get_or_raise`, malformed-JSON deserialize.
- **Zip Slip / reserved-name guard** in `installer._extract_zip` (§4) — deleting the guard breaks no test.
- **`set_thread_context`** write path (§4) — complete blackout.
- **Rust `data_source.rs`** (§13) — `BufferDataSource` read/write/bounds, all error variants; underpins every process-memory read.
- **Rust `templates/eval.rs`** (§13) — DynamicArray / Conditional / StructRef / Pointer evaluator arms (5 of 6); used by PE import/export directory templates.
- **`types.py` exception hierarchies** (§8) — `ProviderError`/`AuthenticationError`/`RateLimitError`/`ModelNotFoundError`, `ToolError`/`ToolNotFoundError`/`InitializationError`/`AttachError`: the contracts every bridge & provider raises.

### Large functional gaps
- **GhidraBridge** (§2): ~56 methods have only a "not connected" guard test (`analyze`, `get_functions`, `decompile`, `search_bytes`, `get_xrefs_from`, `set_data_type`, …).
- **CutterBridge debug subsystem** (§2): 15 ops (attach/detach/breakpoints/step/registers/memory) at 0%, plus project mgmt + write transforms.
- **x64dbg** (§3): trace/patch/anti-debug/PE-directory/TEB/SEH families — ~40 ops, 0%.
- **Frida** (§3): spawn+resume, rpc_call, patch_code, and the entire objc_/java_/kernel_/socket_/file_/sqlite_ families.
- **OpenAI/Ollama offline** (§9): `_iter_openai_stream`, `_open_openai_stream`, `_translate_openai_errors`, `_is_chat_model`, `_infer_context_window`; Ollama `_parse_chat_response`, native tool-call accumulation, `generate`/`embeddings`/`pull_model`.
- **Local-model classification** (§10): `_classify_model_capabilities` (every context-window/vision value), CUDA/XPU load branches, Intel-Arc helpers (`_strip_pwsh_payload` BOM, `_estimate_memory_from_name` VRAM constants).
- **`named_pipe_client` error branches** (§1): malformed JSON, invalid length, non-dict payload, oversized message, already-connected no-op, `_reader_loop` diagnostics.
- **UI zero-coverage modules:** `stack_viewer.py` (§15, entire file), `highlighter.py` (§14, 5 highlighters w/ multi-line state), `_screen_compat.py` (§14, bootstrap path).
- **Hex-editor bridge methods** (§5): `inspect_data_at`, `get_byte_statistics`, `get_content_classification`, bridge-level `insert_bytes`/`delete_bytes`, `test_in_sandbox`.
- **Codegen/Rust value gaps:** 6 hexcore hash algos gated by length only (BLAKE2s, xxh3, siphash64/128, crc8, crc64) (§13); `ScriptManager.delete_script`/`list_scripts` (§8); HexPat function-like macros, eval/pattern depth limits, CRC stdlib (§6).

---

## 5. Prioritized Remediation Plan

### P0 — Rule violations & security gaps (do immediately)
1. Rewrite the 7 forbidden-mock/suppression tests (MV-1…MV-7) using the real-seam patterns already proven elsewhere (`InMemorySandbox`/`LocalProcessSandbox` for §12; real compiler input for MV-2; function-spy for MV-1/MV-5).
2. Add OAuth decision-tree unit tests (§11) — pure deterministic, no keyring: expiry buffers, `get_token` branches, `handle_callback` state/PKCE checks, `revoke_token`.
3. Add Zip Slip / reserved-name adversarial-archive tests and `set_thread_context` read-back test (§4).
4. Add Rust `data_source.rs` OOB/read-only tests and `templates/eval.rs` DynamicArray/Conditional/StructRef/Pointer tests (§13).

### P1 — Close the failing bridge sections
5. Ghidra (§2): reuse `_FakeBridgeClient` to gate the ~56 guard-only methods with real return-value assertions; same for Cutter debug subsystem.
6. x64dbg + Frida (§3): fake-pipe round-trips asserting exact command framing and parsed field values for `get_registers`/`set_register`/`read_peb`/breakpoints; positive `shutdown`/`detach`; `match=` on all bare `pytest.raises`.
7. Provider offline transforms (§9, §10): table-driven `_is_chat_model`/`_infer_context_window`/`_classify_model_capabilities` against published specs; stub-server NDJSON/SSE for stream + tool-call assembly; `_strip_pwsh_payload` BOM oracle.
8. `named_pipe_client` IPC error branches (§1) via the existing `_FakePipe` transport.

### P2 — Replace fake gates with value assertions
9. Delete/rewrite FG-1…FG-18: replace `isinstance`/`len>0`/`>0`/docstring-substring with exact independent oracles (`struct.unpack`, `pefile`, `binascii.crc32`, hashlib, capstone, known constants). Includes `TestInspectAtBasic`, `get_pe_imports`, AI-context, x64dbg register/PEB, `*_no_crash` process tests, `test_sandbox_panel_fixes`, XPU-status, provider length-only schema gate.
10. Replace 6 length-only hexcore hash gates with NIST/known-answer vectors; pin `TemplateRegistry::list_detailed` to `field_count == 20`.

### P3 — Finish the strong-section tails
11. UI zero-coverage modules: `stack_viewer.py`, `highlighter.py` (format-color + multi-line block-state oracle), `_screen_compat.py`.
12. `types.py` exception hierarchies; `ScriptManager.delete_script`/`list_scripts` (§8).
13. HexPat error-class `span`/`data_span`, function-like macros, eval/pattern depth limits, CRC stdlib (§6); hex-editor uncovered bridge methods (§5); orchestrator `shutdown`/`list_sessions`/`delete_session`, mid-pipeline error propagation, JSON export/import (§7).

---

## 6. Audit Caveats (coverage of the audit itself)

- **§9 Cloud Providers** was partial: the agent did not read ~16 provider test files (several `_live`, `test_message_conversion.py`, `test_registry.py`, `test_discovery_unit.py` read only structurally). Operations depending solely on unread files were marked UNKNOWN; registry/discovery were estimated at ~75-80%. Re-run with those files read before treating §9 numbers as final.
- **§6 HexPat** did not read `parser.py`, `stdlib.py` CRC subsystem, or 4 vendor/aux test files in full; parser coverage is inferred from AST assertions (high confidence) and CRC is flagged UNKNOWN.
- **§12 Sandbox** gave a qualitative verdict, not a single percentage; the ~88% in the scorecard is an estimate from its per-area findings.
- **§13 Rust** reasoning was static (no `cargo test` run); 8 of 21 modules have zero in-crate tests.
- All other sections enumerated their full operation set with file:line citations; see the per-section reports for the complete inventory tables.
