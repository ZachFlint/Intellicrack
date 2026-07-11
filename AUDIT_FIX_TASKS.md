# Intellicrack — Audit Fix Task List

**Purpose:** a single, implementable backlog of **OPEN work only**. A task present here means "still open"; a task absent means "done/verified-fixed-live."

**Source reports:**

- `audit/Intellicrack_GUI_Functionality_Audit_2026-07-05.md`
- `audit/Intellicrack_GUI_DeepFunctional_Audit_2026-07-05.md`
- `audit/Intellicrack_GUI_DeepFunctional_Audit_Phase3_2026-07-05.md`
- `audit/Intellicrack_GUI_DeepFunctional_Audit_Phase4_2026-07-10.md` (**latest** — live re-verification)

## How to use this list (read first)

- Work top-down by priority (P0 → P2). Each task is self-contained: **Problem → Root cause (file:line) → Fix steps → Verify**.
- **Line numbers drift** — confirm by searching for the named symbol before editing.
- **Follow `CLAUDE.md` for all code changes:** full type hints, `ruff check` clean, fully basedpyright-clean, `pydoclint`/`pydocstyle` clean, Google-style docstrings, no suppressions, no stubs/TODOs, Windows-first. Do not weaken locked linter/type configs.
- **Every fix needs a real, falsifiable test** under the matching `tests/` area subdir. No asserting-on-mocks, no always-green tests.
- Prefer `pwsh` (PowerShell 7); run Python via the pixi env (`pixi run …`, env at `D:\Intellicrack\.pixi\envs\default`).
- **Launch the app with `--no-elevate`** for any live driving (elevated → Windows UIPI blocks synthetic input).

**Severity legend:** P0 = High · P1 = Medium · P2 = Low/cosmetic.

---

## Status — 2026-07-11 (Phase 5 code-remediation, Phase 1 batch)

**Phase 4** confirmed fixed-live-and-removed: **N1, F1, F5, F13, F10, F15, F14, F8/N4, F11, F2, F6, F3/F18, Export-Analysis-JSON**, duplicate-Analysis-tab, and the menu-open verify-only item.

**Phase 5 batch 1** (code + gated tests, orchestrator-verified RED→GREEN in the Docker sandbox; live GUI re-verification is a separate Phase-6 follow-up) fixed-and-removed:

- **F16** — x64dbg control pipe wedge. Root cause was a Win32 sync-handle concurrent-I/O deadlock (blocked reader thread + concurrent writer on one non-overlapped handle), plus an unguarded concurrent `connect()` and an abandoned-future GC leak. Fixed via real overlapped I/O + per-operation-scoped `CancelIoEx`, a connect lock, and a future-drain callback. Gate: `tests/bridges/test_x64dbg_pipe_recovery.py` (5/5), `tests/bridges/infra/test_named_pipe_client.py` (37/37).
- **x64dbg unretrieved-future leak** (was tied to F16) — folded into the F16 fix; gated by `test_fail_pending_drains_abandoned_future_exception`.
- **F7** — Cutter/rizin backend. Root cause was concurrent OS-thread `.cmd()` calls corrupting the single rizin pipe's NUL framing; fixed with an `asyncio.Lock` serializing all pipe I/O (`_r2_lock`). Context-propagation was already correct. Gate: backend-agnostic `test_concurrent_dispatch_never_overlaps_pipe_access` + a real lock-free-adapter `test_concurrent_commands_return_self_consistent_output` in `tests/bridges/test_realcov_03c_cutter.py`.
- **Hex Editor hexcore document not opened on load** (P1) + **hex-editor auto-parse race** (P2) — both one root cause: the panel opened its own `HexDocument` but never told the bridge. Fixed via a new `HexEditorBridge.adopt_document`. Gate: `tests/bridges/completeness/hex_editor/test_load_file_bridge_document_wiring.py` (4/4).

**Pre-existing defects found this pass (NOT introduced by Phase 5; logged for separate follow-up):**

- `tests/bridges/test_realcov_03c_cutter.py::TestRealMetadata::test_relocations_real` — rizin/radare2-version relocation-vaddr decoding mismatch vs the `pefile` oracle on this OS build's kernel32.dll. Fails on clean main; unrelated to F7.
- `tests/bridges/test_x64dbg_plugin_pipe_failfast.py` (1 test) — `AttributeError: module 'intellicrack.bridges.x64dbg' has no attribute 'Popen'`; stale from the `4f5a4c72` process-isolation refactor (x64dbg spawning moved to `spawn_on_hidden_desktop`).

**Phase 5 batch 2** (code + gated tests, orchestrator-verified RED→GREEN in the sandbox) fixed-and-removed:

- **F4** — Function → Cross References never populate. Root cause: `_select_static_analysis_bridge` unconditionally preferred Cutter, whose `state.connected` flips True on rizin-backend init before any binary is loaded through it, so an open-but-unloaded Cutter starved the healthy Ghidra bridge. Fixed with a `_bridge_is_healthy` check (connected AND binary_loaded AND no last_error) + Ghidra fallback. Gate: `tests/ui/tools/test_function_xref_population.py` (12/12).
- **HuggingFace `Bearer ` illegal-header** (P1) + **Ollama WinError 10061** (P2) — one shared root cause: `MainWindow._on_refresh_models` never passed the already-connected provider instance to `ModelRefreshWorker`, so `_fetch_models` fell through to a raw-HTTP path building `Bearer ` from an empty token (HF) / hitting dead localhost (Ollama). Fixed by resolving the connected instance from the registry and passing it as `provider=`, so the worker reuses the authenticated client. Gate: `tests/providers/test_provider_refresh_toolbar_bugfixes.py` (21/21).
- **Provider default is a non-chat media model** (P2) — `OpenAIProvider`/`GrokProvider._is_chat_model` didn't exclude video/image models, so reverse-sorted catalogs defaulted to `sora-2-pro`/`grok-imagine-video-*`. Fixed with media-prefix/`imagine` filters. Gated in the same providers test.
- **Ghidra in-panel Load before Start-Headless → WinError 10061** (P2) — `GhidraBridge.initialize()` marked the bridge connected on lazy client construction without probing whether a server was listening, so the panel enabled Load and the first RPC hit ConnectionRefused. Fixed with a real `_probe_bridge_port` liveness check + clear "not reachable, start headless" message, gating the panel Load button. Gate: `tests/bridges/test_ghidra_load_gate.py` (2/2).

**Phase 5 batch 3** (code + gated tests, orchestrator-verified RED→GREEN in the sandbox) fixed-and-removed:

- **Light theme applies inconsistently** (P2) — the panels already re-theme on `theme_changed`; the live defect (verified by driving the real GUI) was `QMenuBar`/`QToolBar` staying dark after a runtime toggle because Windows Qt caches the first polish. Fixed with `ThemeManager._repolish_chrome` (unpolish/polish/update the chrome widgets) after every `setStyleSheet`. Gate: `tests/ui/test_theme_manager.py::TestMenuBarToolbarRuntimeRepolish` — a recording-style stand-in asserts the chrome widgets are actually re-unpolished on toggle (offscreen-falsifiable, since the pixel approach can't discriminate this).
- **Process → Memory content read fails + Threads/Modules need manual Refresh** (P2) — memory Read defaulted to an unset address; threads/modules never auto-populated on attach. Fixed by seeding the default read address to the main module base and auto-refreshing threads/modules on attach + tab-activate. **Also found+fixed a real production bug the test caught:** `MemoryTab._on_read` checked `isinstance(result, bytes)` but `ProcessBridge.read_memory` returns a hex `str`, so the Read tab silently no-op'd for *every* address — now decodes `bytes.fromhex`. Gate: `tests/ui/test_process_panel_attach_autopopulate.py` (6/6) against a real `ProcessBridge` attached to the live test process.
- **Right-hand Functions side-list not cleared on unsupported/invalid load** (P2) — `reset_analysis` cleared the analysis panel but not the independently-populated `func_list`/`xref_panel`. Fixed by also clearing both. Gate: `tests/ui/test_tools_reset_analysis_clears_functions.py` (3/3).
- **Branding: About/splash wordmark read "IntelliCrack"** (P2) — the wordmark was baked pixel data in `splash.png`. Regenerated the asset via a new deterministic `build_splash_image()` that composites a frozen `splash-wordmark.png` (rendered from the bundled JetBrainsMono-Bold.ttf). Gate: `tests/ui/test_splash_screen.py::TestSplashAssetGeneration` — asserts the shipped PNG is pixel-exact-equal to `build("Intellicrack")` and NOT `build("IntelliCrack")` (OCR-free, falsifiable by reverting the asset).
- **N2 — Docked tool panels clipped even when maximized** — the left dock floor was a static 240px while the real Frida/Cutter/Ghidra tabs need 991/621/450px, so the splitter squeezed the active tab below its render minimum. Fixed with a dynamic floor that tracks the active tab's `minimumSizeHint()`. Gate: `tests/ui/test_dock_panel_min_width.py` (5/5).
- **F17 — Cancel leaves a lingering "cancelled" state** — verified **already fixed** in commit `4f5a4c72`: `Orchestrator`'s request `finally` clears `_cancel_event` + resets `_state="idle"` on every unwind, gated by the committed `tests/core/test_orchestrator_cancel_settle_f17.py` (2/2, confirmed passing). Removed as already-resolved.
- **Model-combo field end-truncation** — verified **already fixed**: the toolbar model combo uses `AdjustToContents` sizing and a `currentTextChanged` tooltip carrying the full id, gated by the committed `tests/ui/test_branding_and_model_combo.py` (3/3, confirmed passing). Removed as already-resolved.

---

**Backlog empty.** All Phase-4 open items are code-fixed with real, sandbox-verified falsifiable gates (each watched RED-on-revert → GREEN-on-restore by the orchestrator). Whole `src/` tree is basedpyright/ruff/pydoclint/pydocstyle clean on the merged branch. **Live GUI re-verification is a separate Phase-6 follow-up** — this pass delivers code + gated tests, not live-driven confirmation.

Pre-existing defects surfaced during this pass (NOT introduced here; logged for separate follow-up): `tests/bridges/test_realcov_03c_cutter.py::TestRealMetadata::test_relocations_real` (radare2 relocation-vaddr decoding vs `pefile` oracle) and `tests/bridges/test_x64dbg_plugin_pipe_failfast.py` (stale `x64dbg.Popen` attribute from the `4f5a4c72` process-isolation refactor).
