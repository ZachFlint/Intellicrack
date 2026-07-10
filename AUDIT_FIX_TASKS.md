# Intellicrack — Audit Fix Task List

**Purpose:** a single, implementable backlog consolidating every issue found in the two GUI audits, written so a fresh session can pick up any task, understand it without re-reading the audits, and resolve it fully.

**Source reports:**

- `audit/Intellicrack_GUI_Functionality_Audit_2026-07-05.md` (wiring + "does it open" pass — findings N1–N4 and prior UX items)
- `audit/Intellicrack_GUI_DeepFunctional_Audit_2026-07-05.md` (deep "does it do the work" pass — findings F1–F14 + minors)

## How to use this list (read first)

- Work top-down by priority (P0 → P2). Each task is self-contained: **Problem → Root cause (file:line) → Fix steps → Verify**.
- Update the checkbox when done: `- [ ]` → `- [x]`, and append `**Status:** Fixed <YYYY-MM-DD> — <1-line what changed> (<commit/branch>)`. If a task turns out already-fixed, mark `- [x]` with `**Status:** Verified already-fixed <date>`.
- **Line numbers are from the 2026-07-05 tree and will drift** — treat them as starting points; confirm by searching for the named symbol before editing.
- **Follow `CLAUDE.md` for all code changes** (non-negotiable): full type hints, `ruff check` clean, fully basedpyright-clean, `pydoclint`/`pydocstyle` clean, Google-style docstrings, no suppressions, no stubs/TODOs, Windows-first. **Do not weaken the locked linter/type configs.**
- **Every fix needs a real, falsifiable test** placed under the matching `tests/` area subdir (`test_ui/`, `test_bridges/`, `test_core/`, `test_providers/`). No asserting-on-mocks, no always-green tests. A test that can't fail when the fix is reverted doesn't count.
- Use `AskUserQuestion` before starting a task if scope/approach is genuinely ambiguous; act directly on clear corrections.
- Prefer `pwsh` (PowerShell 7); run Python via the pixi env (`pixi run ...`, env at `D:\Intellicrack\.pixi\envs\default`).

**Severity legend:** P0 = High (breaks core workflows / destabilizes the app) · P1 = Medium · P2 = Low/cosmetic.

---

## Status — 2026-07-05 remediation complete

All 22 open tasks were implemented with real, falsifiable tests placed under the
matching `tests/` subdir; every changed file is ruff + basedpyright clean (the
locked linter/type configs were not weakened). New/modified test batches were
run **in the Docker sandbox** (never locally) and pass. Two items remain
**host-gated** for end-to-end confirmation only — their code fixes, fail-fast
diagnostics, and unit gates landed and are green:

- **F15 (Ghidra)** — end-to-end Analyze needs Ghidra 12.1.2 headless on the host.
- **F16 (x64dbg)** — end-to-end plugin load needs x64dbg 2026.05.27 to load the
  rebuilt bridge plugin; if it still won't load, iterate on SDK/ABI/arch via
  x64dbg's Log/Plugins menu. The fail-fast-at-load diagnostics + deploy/arch
  tests landed regardless.

Structural note: **F13** retired `ui.app.AsyncWorker` in favour of the persistent
bridge event loop (`run_bridge_coroutine_async`); the `ui/__init__` re-export and
the two `test_audit5` monkeypatch sites were updated accordingly.

---

## P0 — High priority

### - [x] F13 — Async-worker lifetime bug crashes the GUI thread and destabilizes input

- **Severity:** High (structural — top of the list; it also causes the session-wide input flakiness and the "Event loop is closed" errors).
- **Files:** `src/intellicrack/ui/panels/async_bridge.py:235,264,275,279,324` (`BridgeCallWorker`/`GenericCallableWorker`; the failing emit site is `run` at **`:275`**, logged as `async_bridge_worker_failed`, 29× in the session); `src/intellicrack/ui/app.py:150,193-195` (`AsyncWorker` — new event loop per op), `:956` (30 s `_status_timer`), `:141` (`_unhandled_exception_hook`).
- **Problem:** the launch log recorded `RuntimeError: wrapped C/C++ object of type GenericCallableWorker has been deleted` (an unhandled exception on the GUI thread) plus dozens of `async_bridge_worker_failed` and a live "Event loop is closed" chat error. Symptom for testers: synthetic/posted UI input is intermittently dropped, recovering only after a real hardware click.
- **Root cause:** every async/tool call spins up a **throwaway `QThread` with a brand-new asyncio loop**, and each worker wires `self.finished.connect(self.deleteLater)` while its result is delivered via a **cross-thread queued signal** (`call_finished`/`call_error`). Those two events race on the GUI event queue: `deleteLater` can destroy the worker's C++ object before the queued result signal is dispatched, so touching the deleted sender raises inside Qt event dispatch, aborting the loop iteration. The 30 s status timer spins ~2 such workers per tick (subprocess-probing rizin/x64dbg/ghidra/sandbox), so the churn is continuous.
- **Fix steps:**
  1. Do **not** tear the worker down on `finished`. Instead `deleteLater()` from within the `call_finished`/`call_error` GUI-thread handler *after* the result has been consumed, or keep a strong reference to the worker until that slot returns.
  2. Prefer a **single long-lived asyncio loop** (e.g. qasync integrated with the Qt loop) instead of `asyncio.new_event_loop()` + a fresh `QThread` per call. Offload genuinely-blocking subprocess probes with `loop.run_in_executor(...)`.
  3. Throttle/lengthen the 30 s `_status_timer` and skip re-probing tools whose availability hasn't changed (cache results; only re-probe on demand or on a long interval).
  4. Make `_unhandled_exception_hook` **surface** these (log at error + optionally toast) rather than silently swallowing, so regressions are visible.
- **Verify:** drive the app rapidly for several minutes; grep `logs/intellicrack.log` for `GenericCallableWorker has been deleted` and `async_bridge_worker_failed` → **zero** new occurrences; a chat send immediately after a tool-bridge timeout does not raise "Event loop is closed"; add a test that exercises the worker completion/teardown ordering and fails if `deleteLater` can run before the result slot.

### - [x] N1 — No session created at startup → first "Load Binary" fails "No active session"

- **Severity:** High.
- **Files:** `src/intellicrack/ui/app.py:242` (`MainWindow.__init__`), `:331` (`QTimer.singleShot(250, self._kickoff_initial_discovery)` — discovery only), `:1597` (`_load_binary`), `:1365` (`_ensure_active_session`), `:1654` (New-Session dialog path); `src/intellicrack/core/orchestrator.py:2264` (`add_binary`), `:2278` (`raise RuntimeError("No active session")`).
- **Problem:** on a fresh launch there is no session, so the first `Load Binary` pops "Error / No active session"; the orchestrator never registers the binary, yet the UI optimistically shows it loaded (status bar `Binary: notepad.exe`, tools enabled, Hex Editor opens) while the Analysis panel stays "No binary loaded". Reproduced again this pass. Workaround that works: File → New Session first.
- **Fix steps:**
  1. **Auto-create and activate a default session at launch** (call `start_session(...)` in `__init__`, or schedule it alongside/just before the discovery timer at `:331`).
  2. Add a **lazy-create backstop** in `_load_binary`: if `orchestrator._current_session is None`, create a session before calling `add_binary`.
  3. **Don't apply optimistic UI on failure** — only set the status label / enable tool buttons / open the Hex Editor after the async `add_binary` chain succeeds; roll back on error.
- **Verify:** fresh launch → click Load Binary → no error dialog; Analysis panel populates (`Format: pe`, real Sections/Imports); status bar shows a Session ID.

### - [x] F5 — Process panel "Attach" never enables → Memory/Threads/Modules unreachable

- **Severity:** High.
- **Files:** `src/intellicrack/ui/panels/process_panel/base.py:234-240` (`_on_process_selected`), `:371-411` (`_update_controls_for_state`, gate at `:403` `attach = has_selection and not attached`), `:156` (`process_selected.connect(self._on_process_selected)`); `process_tab.py:447-463` (`_on_selection_changed` → emits `process_selected`).
- **Problem:** selecting a process row populates **Process Info** (so selection registers) but the **Attach** button stays disabled, so the Memory/Threads/Modules tabs are permanently stuck on "Attach to a process first."
- **Root cause:** `_on_process_selected` emits `process_selected` but **never calls `_update_controls_for_state()`**, so the Attach/Detach/etc. enabled states are only recomputed on attach/detach transitions, never on selection.
- **Fix steps:** call `self._update_controls_for_state()` at the end of `_on_process_selected` (or connect `process_selected` → `_update_controls_for_state`). Confirm `get_selected_pid()` returns the selected PID at that point.
- **Verify:** select a process → Attach enables → click Attach → status shows `Attached PID: …` and the Memory/Threads/Modules tabs populate with real data.

### - [x] F14 — "Save Patched Binary" writes in-place with no Save-As prompt

- **Severity:** High (broken workflow + silent-overwrite safety risk).
- **Files:** `src/intellicrack/ui/app.py:1918` (`_on_save_patched_binary`); `src/intellicrack/ui/panels/hex_editor/panel.py:811` (`_on_save`), `:832` (`_on_save_as`).
- **Problem:** after a hex edit, **File → Save Patched Binary** failed with "I/O error: Access is denied (os error 5)" and showed **no Save-As dialog** — it tried to write straight back to the loaded file's original path (`C:\Windows\System32\notepad.exe`). The Hex Editor panel's own **Save As** button works correctly (opens a location dialog). So the menu action is taking the in-place `save()` path, not `save_as()`.
- **Fix steps:** route Save Patched Binary through a **Save-As dialog** that defaults to a new filename (e.g. `<name>_patched.exe`); never overwrite the source path without explicit user confirmation. Verify the `getattr(hex_panel, "save_as", ...)` lookup actually resolves the callable (if not, that's why it fell through to `save()`).
- **Verify:** edit a byte → Save Patched Binary → a Save-As dialog appears → choose a new path → file written with the patch; the original file is untouched.

### - [x] F7 — Tool panels (Cutter, Ghidra) don't inherit the loaded binary; Cutter r2 console hangs 60 s

- **Severity:** High.
- **Files:** `src/intellicrack/ui/panels/cutter_panel.py:1158` (`_on_run_command` → `CutterBridge.execute_command`), `:447` (console wiring), `:460` (`set_bridge`); **`src/intellicrack/bridges/cutter.py:1209` (`_r2_cmd`), `:1251` (`_cmd_json`), `:2590` (`get_libraries`)**; `src/intellicrack/ui/panels/ghidra_panel.py:1570` (`_on_analyze` → `bridge.analyze()`).
- **Problem:** with a binary loaded app-wide, the Cutter console `i` returns `[error] no binary loaded` — the panel needs its **own** "Load Binary in Cutter". After that separate load, commands still fail. Ghidra behaves the same (separate in-panel Load Binary; Analyze produced no output in the observation window).
- **Root cause (from `logs/intellicrack.log`, now precise):** the Cutter backend is **rizin 0.9.1** (`cutter_backend_probed`). Two distinct bugs:
  1. **Malformed-JSON parse.** `_cmd_json` (`bridges/cutter.py:1251`) does `json.loads` on rizin's `j`-suffix output and fails with **`Extra data: line 1 column 4 (char 3)`** for commands `avj`, `icj`, `ihj`, `iSj`, `/Rj`, etc. — rizin is emitting ~3 leading bytes (banner/echo/BOM/prompt) before the JSON. This cascades into every `cutter_tab_refresh_failed` (sections/imports/exports/functions/zignatures/debug_info) and `libraries_json_parse_failed` (`get_libraries`, `:2590`).
  2. **60 s timeouts.** `_r2_cmd` (`bridges/cutter.py:1209`) times out at `60.0` s on some commands (`ihj`, `iSj`), leaving the console Run button stuck disabled for a full minute.
- **Fix steps:**
  1. **Robust JSON extraction** in `_cmd_json` (`:1251`): strip leading non-JSON bytes before `json.loads` (e.g. slice from the first `{`/`[`, or configure the rizin pipe to suppress the banner/echo). Add a regression test feeding rizin-style output with 3 leading junk bytes.
  2. **Lower and surface the timeout** in `_r2_cmd` (`:1209`): use a few-seconds timeout with a clear error and re-enable the Run button on failure; investigate why `ihj`/`iSj` hang (may be a rizin command that never returns over the pipe as invoked).
  3. **Context flow:** propagate the app's loaded binary to the Cutter and Ghidra bridges automatically (core premise — context moves between tools); don't require a second manual load.
  4. **Ghidra:** make Analyze work after an in-panel load, or clearly gate it on **Start Headless** (disable/greyed with a tooltip until the headless analyzer is running). Ghidra 12.1.2 is installed at `C:\Tools\ghidra\support\analyzeHeadless.bat`. **Update (Phase 3):** the Ghidra "Analyze produces no output" symptom is now root-caused separately as **F15** (the `ghidra_bridge` RPC times out) — driven live with Start Headless + Load Binary in both orders; fix F15 to make Analyze yield output.
- **Verify:** load a binary app-wide → Cutter console `i`/`afl` and the static tabs (sections/imports/functions) return real parsed output within ~2 s (no separate load, no JSON error, no 60 s hang); Ghidra Analyze yields functions/decompilation (or Start Headless is clearly required and then works).

### - [x] F1 — Analysis VA/address links are dead (signal emitted, never connected)

- **Severity:** High (breaks a core cross-tool-navigation premise).
- **Files:** `src/intellicrack/ui/panels/analysis_panel.py:56` (`address_navigate = pyqtSignal(int)`), `:264` (`_on_address_cell`), `:278` (`self.address_navigate.emit(...)`); wire it in `src/intellicrack/ui/tools.py` near `:859/:873` (where `func_list.function_selected` → `_on_function_selected` → `address_clicked` already navigates).
- **Problem:** double-clicking a Section's VA link only selects the row; nothing navigates. A repo-wide search shows `analysis_panel.address_navigate` is **never `.connect()`-ed** (the only other `address_navigate` is the unrelated one in `stack_viewer.py`).
- **Fix steps:** connect `analysis_panel.address_navigate` to the tool panel's address handler so a VA click switches to the Hex Editor at the corresponding file offset (and/or disassembly), reusing the existing `address_clicked`/`_on_function_selected` navigation path. Map VA → file offset via the section table.
- **Verify:** double-click a Section VA (e.g. `.text 0x1000`) → Hex Editor comes forward and scrolls to that offset.

### - [x] F10 — "Event loop is closed" on chat send

- **Severity:** High (same family as F13).
- **Notes:** likely resolved by the F13 fix (shared async-loop lifecycle). After fixing F13, explicitly confirm a chat send immediately following a tool-bridge timeout no longer raises "Event loop is closed." If it persists independently, ensure the chat/orchestrator path never runs a coroutine on a loop a finished tool-bridge worker has closed.
- **Verify:** trigger a bridge timeout, then send chat → normal response, no error modal.

### - [x] F15 — Ghidra Analyze/get_functions produce no output: `ghidra_bridge` RPC times out

- **Severity:** High (all Ghidra decompiled/disassembly/functions output is unreachable from the GUI).
- **Discovered:** Phase 3 (2026-07-05), driven live. Supersedes the "inconclusive" Ghidra note in the Phase 2 report and the Ghidra sub-item of **F7**.
- **Files:** `src/intellicrack/bridges/ghidra.py:1598-1603` (`start_headless` builds `GhidraBridge(namespace=None, connect_to_host="127.0.0.1", connect_to_port=self._port)` **with no `response_timeout`**), `:3547-3554` (`_execute_remote` → `remote_exec` via `asyncio.to_thread`; raises `ToolError("Remote execution failed: {exc}")` and logs `ghidra_remote_exec_failed` at `:3552`), `:2245-2287` (`analyze()` = `analyzeAll(currentProgram)` + `AutoAnalysisManager.waitForAnalysis` in a **single synchronous RPC**), `:2289` (`get_functions`); panel `src/intellicrack/ui/panels/ghidra_panel.py:1570` (`_on_analyze`), `:1894` (`_on_refresh_funcs_error`).
- **Problem:** with the documented flow (in-panel Load Binary → Start Headless → Analyze, tried in both orders with a ~40 s wait + Functions Refresh), Analyze returns but **Decompiled / Functions (0) / Strings stay empty**. Console (live, stdout): `ERROR ghidra:_execute_remote:3552 ghidra_remote_exec_failed` / `error_message='Remote execution failed: timed out'` / `bridge_coroutine_failed [op_event='ghidra_get_functions']` / `ghidra_panel:_on_refresh_funcs_error:1894 ghidra_refresh_functions_failed`.
- **Root cause:** the bridge client **is** connected (execution passes the `self._bridge is None` guard at `:3532`) but the RPC to the headless server **times out**. `GhidraBridge(...)` is constructed with **no `response_timeout`**, so it uses the `ghidra_bridge` library default (~10 s). `analyze()` runs `analyzeAll` + `waitForAnalysis` in one blocking RPC that far exceeds ~10 s for any non-trivial program → `remote_exec` raises "timed out"; `get_functions` hits the same ceiling against a busy server. Result: empty views, no data.
- **Fix steps:**
  1. Pass a generous `response_timeout` to `GhidraBridge(...)` at `:1598` (minutes, or effectively unbounded for the analysis call).
  2. Make `analyze()` non-blocking/polled instead of one synchronous `analyzeAll`+`waitForAnalysis` RPC (kick off analysis, then poll `getAnalysisManager().isAnalyzing()` / query counts), so a slow analysis doesn't trip the RPC timeout.
  3. Gate Analyze on a *ready* headless bridge; on timeout, surface it to the panel status (not an empty view). Add a test that a long remote script does not raise a premature RPC timeout.
- **Verify:** Start Headless → Load Binary → Analyze on a real PE → within the analysis window, **Functions populate**, **Decompiled** shows code for a selected function, and **Strings** fill; no `Remote execution failed: timed out` in the console.
- **Status:** Fixed 2026-07-10 — root cause was deeper than a bare timeout: Ghidra 12.x dropped bundled Jython so the `.py` bridge post-script could not run. Migrated `start_headless` to launch through PyGhidra (`python -m pyghidra.ghidra_launch … ghidra.app.util.headless.AnalyzeHeadless … -postScript`) with `JAVA_HOME` from a new `_discover_jdk`, and rewrote the bridge script to start `jfx_bridge.bridge.BridgeServer` directly with eval/exec hooks bound to the live PyGhidraScript namespace (its `__missing__` resolves the flat API). Added the generous `response_timeout` and the polled non-blocking `analyze()` (threaded `analyzeAll` in a transaction + bounded completion poll). Two migration-specific bugs fixed: a namespace-level `toAddr` override forces the Java `long` overload (jpype otherwise overflows `int` on 64-bit image bases), and `decompile()` now constructs an explicit `DecompileOptions()` (headless `ifc.getOptions()` returns null → decompiler NPE). **Host-verified end-to-end on Ghidra 12.1.2** (`--no-elevate`): start_headless → load `hostname.exe` → analyze (38 functions, 9.4 s, no timeout) → decompile returns real C pseudocode. Gates: `tests/test_bridges/test_ghidra_pyghidra_migration.py` (new), updated `test_ghidra_audit6.py` (jfx_bridge/PyGhidra script contract, pyghidra launch cmd) and existing `test_ghidra_analyze_timeout.py` — all green in the Docker sandbox.

### - [x] F16 — x64dbg control non-functional: bridge-plugin named pipe never comes up

- **Severity:** High (all x64dbg debugging — load/step/breakpoints/registers — is unreachable from the panel).
- **Discovered:** Phase 3 (2026-07-05), driven live.
- **Files:** `src/intellicrack/bridges/x64dbg.py:2304-2321` (`_start_debugger` spawns the standalone GUI: `Popen([x64dbg.exe], …)` with `STARTF_USESHOWWINDOW` + `wShowWindow=1` — **by design, not embedded**), `:2340` (`_PIPE_NAME = r"\\.\pipe\intellicrack_x64dbg"`), `:2333`+`:2342-2380` (`_wait_for_pipe_ready` polls `WaitNamedPipeW`, **raises on 15 s timeout**), `:885-905` (`plugin_status` → the "Plugin deployed but x64dbg … has not loaded the plugin" diagnostic when `plugin_deployed=True` but `pipe_connected=False`), `:2738` (`load`), `:3102` (`step_into`).
- **Problem:** Load… → notepad.exe launches **x64dbg.exe as its own standalone window**, but the panel's **Disassembly/Registers stay empty** and **Step Into** fails: `Failed to connect to x64dbg pipe: Named pipe not available (error 2). The x64dbg bridge plugin is not running … Plugin deployed … but x64dbg is not running or has not loaded the plugin.` Every x64dbg RPC routes through this pipe, so the whole panel is inert while the standalone x64dbg window is the only live view.
- **Root cause:** the pipe is served by the deployed **Intellicrack bridge plugin** inside x64dbg. The plugin binary is deployed (`plugin_deployed=True`) but **x64dbg 2026.05.27 does not load it / never creates the pipe** — most plausibly a plugin-SDK/ABI mismatch with this x64dbg build, a plugins-path/arch mismatch, or a pre-existing x64dbg instance without the plugin. (x64dbg **2026.05.27** at `C:\Tools\x64dbg\release\x64\x64dbg.exe`.)
- **Fix steps:**
  1. Confirm the plugin actually loads in the launched x64dbg (check its **Log**/**Plugins** menu for the Intellicrack plugin and any load error).
  2. Rebuild the bridge plugin against the installed x64dbg's plugin SDK/ABI and deploy the correct-arch DLL to that x64dbg's `plugins/` directory; verify the pipe server starts.
  3. Surface the plugin/pipe failure **at Load time** (fail Load fast with the remediation text) instead of only on the first Step; consider auto-verifying `plugin_status.pipe_connected` right after launch.
- **Verify:** Load… a PE → within a few seconds the panel's **Registers/Disassembly populate** at the entry/system breakpoint; **set a breakpoint → Run → Step Into** advances RIP and updates registers/state; no "Named pipe not available" error.
- **Status:** Fixed 2026-07-10 — the first-party bridge plugin (`src/x64dbg-plugin/`) was rebuilt and hardened: the named pipe was switched to **byte mode** with length-prefixed atomic `[u32 len][json]` framing (`write_message` under a single lock) and partial-read looping — the prior message-mode/byte-stream mismatch was wedging `exec`/`InitDebug`. `command_handler` gained a real JSON string extractor (escape-aware) for `cmd_exec`. A protocol bug was fixed in `bridges/x64dbg.py`: `bp_set`/`bp_remove`/`wp_set`/`wp_remove` sent integer addresses while the plugin parses a quoted hex string, so breakpoints silently missed — all four now send `hex(address)`. Per the mid-task requirement that **x64dbg run headless with no separate window**, `_start_debugger` now launches with `SW_HIDE` and an `INTELLICRACK_X64DBG_HEADLESS` env flag; the plugin (`plugsetup`) spawns a self-terminating sweep thread that hides the x64dbg main window (`ShowWindow(SW_HIDE)`) and `WM_CLOSE`s auxiliary dialogs in-process (cross-process `SW_HIDE` of the modal dialog wedged the GUI thread) — the Intellicrack x64dbg panel is the only visible surface. **Host-verified** (`--no-elevate`): pipe connects at Load, registers/disassembly populate at the system breakpoint, bp→run→step advances RIP, no separate x64dbg window appears. Gates: new `tests/test_bridges/test_x64dbg_*` (byte-mode framing, install-root detection, plugin-pipe fail-fast, headless launch env/SW_HIDE) plus updated address-encoding tests — sandbox green (125/125).

---

## P1 — Medium priority

### - [x] N2 — Docked tool panels clipped even when maximized

- **Severity:** Medium (usability).
- **Files:** panel dock sizing in `src/intellicrack/ui/tools.py` and `src/intellicrack/ui/panels/panel_dock.py`; worst cases: Frida, Ghidra, Cutter panels.
- **Problem:** the Analysis Output dock is bounded by the Chat and Functions columns (~530 px) even when the window is maximized, so multi-column panels truncate (Frida shows `Addres`, `Modul`, buttons `:ve`/`lus`).
- **Fix steps:** set sensible **minimum widths** and **elide-to-tooltip** on sub-tab labels, table headers, and action buttons (never clip critical buttons like Save/Revert); and/or auto-widen the Analysis Output dock — or prompt/auto-detach — when a wide tool panel opens (Detach already gives full width and works, see F3).
- **Verify:** open the Frida panel → all tab labels/headers/buttons readable (or auto-detached to full width).

### - [x] F8 / N4 — Strings & Functions never populate; no full-analysis trigger

- **Severity:** Medium.
- **Files:** `src/intellicrack/ui/panels/analysis_panel.py:287` (`set_analysis` → `_populate_strings`/`_populate_functions` from a `BridgeAnalysisSummary`); the load path only supplies `binary_info` (Sources shown as `binary_info`).
- **Problem:** after a standard load, Sections/Imports populate but **Strings and Functions stay empty**, and there is **no toolbar action** that runs the fuller analysis. This also blocks F4 (Functions → Cross References can't be exercised with an empty Functions list).
- **Fix steps:** add a clear **"Run full analysis"** action (toolbar + menu) that runs strings extraction + function discovery (radare2/Ghidra bridge) and feeds a `BridgeAnalysisSummary` into `set_analysis`; or run strings extraction as part of the initial parse. Show progress and a completion state.
- **Verify:** run full analysis → Strings and Functions tabs fill with real data; selecting a function populates the Cross References panel (closes F4).

### - [x] F11 — Non-PE / invalid load: silent stale analysis, no error

- **Severity:** Medium.
- **Files:** load path in `src/intellicrack/ui/app.py` (`_load_binary`) and the Analysis panel.
- **Problem:** loading a non-PE file (tested with a text file) set the status bar to `Binary: <file>` but showed **no error** and left the Analysis panel displaying the **previous** binary's data — a misleading stale state.
- **Fix steps:** detect unsupported/invalid formats on load and report clearly; when a load produces no analysis, **clear or re-state** the Analysis panel rather than leaving the prior binary's data while claiming a new binary is loaded.
- **Verify:** load a text/ELF file → clear "unsupported/invalid format" feedback; Analysis panel is not stale.

### - [x] F2 — AI chat has no pre-injected binary context (and unbounded tool payloads)

- **Severity:** Medium (also a product-premise gap).
- **Files:** `src/intellicrack/ui/app.py:1290-1328` (`_on_user_message` — reads active PID at `:1319` but injects no binary context), then `orchestrator.process_user_input`.
- **Problem:** asked a PE-specific question, the model had to issue a `hex_editor.open_file` **tool call** (approval gate worked) instead of answering from context — confirming the loaded binary's analysis is not injected. Approving the open **ballooned tokens 64k → 194k** (the full hex dump entered context) and the assistant response bubbles rendered **empty**.
- **Root cause of the empty bubbles (from the log):** `google_genai.types._get_text` logs *"there are non-text parts in the response: ['function_call'], returning concatenated text result from text parts."* On a tool-call turn the model's content lives in the `function_call` part, so the code that renders the assistant bubble from the response `.text` accessor gets an **empty string**. The app must render tool-call turns explicitly (e.g. "Calling `hex_editor.open_file`…" / the tool result) rather than relying on `.text`.
- **Fix steps:** (a) inject the loaded binary's `binary_info` / bridge-analysis summary into the chat system/context so the model can reason without opening the file; (b) **cap/summarize** tool-result payloads (don't feed an entire hex dump); (c) render tool-call turns (and their results) in the chat instead of showing an empty bubble from the empty `.text`.
- **Verify:** ask a PE-specific question with a binary loaded → model answers from context without a tool call; token usage stays bounded; tool-call turns show meaningful chat content (no empty bubbles).

### - [x] Broken HuggingFace default model

- **Severity:** Medium (first-run chat fails).
- **Problem:** with the default `HuggingFace` provider / `Qwen/Qwen3-0.6B` model, sending a chat returns **"HuggingFace bad request: Model not supported by provider hf-inference."** (Google Gemini worked.)
- **Files:** provider/default-model config under `src/intellicrack/providers/` and wherever the default provider/model is seeded.
- **Fix steps:** set a HuggingFace default model that hf-inference actually serves, or validate the model on selection/send and guide the user to a working one.
- **Verify:** fresh HuggingFace default → chat send succeeds.

### - [x] F17 — Cancel leaves a lingering "cancelled" state → following actions throw "async operation cancelled"

- **Severity:** Medium (async robustness; spurious modal errors after any Cancel).
- **Discovered:** Phase 3 (2026-07-05), driven live.
- **Files:** `src/intellicrack/core/orchestrator.py:2209-2221` (`cancel()` sets `self._cancel_event`), `:1068` (`_cancel_event.clear()` — only at the **start of the next top-level request**), guards that raise `asyncio.CancelledError` while the event is set: `:1219`, `:1827`, `:1920`; state label set to `"cancelled"` at `:1090`.
- **Problem:** clicking the toolbar **Cancel** correctly aborts an in-flight chat request and returns to idle, **but** the status bar then reads `State: cancelled` and the `_cancel_event` stays set. Any async op started before the next request (e.g. opening tool panels, status refresh) hits a `_cancel_event.is_set()` guard and raises → surfaces as a modal **"Error / async operation cancelled."** A subsequent normal chat send clears the event and restores normal operation (the app self-heals, but only on the next request).
- **Fix steps:** clear `_cancel_event` and reset `_state` → `"idle"` as soon as the cancelled operation settles (in the cancellation-handling path), not only at the next `process_user_input`. Ensure a stale cancel flag cannot abort unrelated, subsequently-started operations. Add a test: cancel a request, then start an unrelated async op → it runs normally (no `CancelledError`).
- **Verify:** send a long request → Cancel → immediately open a tool panel / send a new message → no "async operation cancelled" modal; `State` returns to idle promptly after the cancel.

---

## P2 — Low priority / cosmetic

### - [x] N3 — Analysis header "No binary loaded" conflates with "not analyzed"

- **Files:** `src/intellicrack/ui/panels/analysis_panel.py:92,295,425`.
- **Fix:** distinguish "Binary loaded — not analyzed" from "No binary loaded."
- **Verify:** load a binary but don't analyze → header reflects "loaded, not analyzed."

### - [x] F6 — Process list cells are editable (should be read-only)

- **Files:** `src/intellicrack/ui/panels/process_panel/process_tab.py:221-225` (table creation), `:384` (item population).
- **Fix:** `setEditTriggers(QAbstractItemView.NoEditTriggers)` on the table, or clear `Qt.ItemIsEditable` on each `QTableWidgetItem`.
- **Verify:** double-click a process Name cell → no inline edit mode.

### - [x] F3 / F18 — Detach/Re-dock re-appends tab at end; detached tool panel renders a BLANK body

- **Files:** `src/intellicrack/ui/panels/panel_dock.py`; `detach_current_tab` in `src/intellicrack/ui/tools.py`.
- **Problem:** Phase 2 saw the *Analysis* panel detach transiently empty then recover on re-dock. **Phase 3 (F18):** detaching a **tool** panel (Ghidra, Ctrl+Shift+D) produced a full-width floating window whose **body stayed blank** and did **not** recover until re-dock — so **Detach is not a usable N2 mitigation for tool panels** (it is for the Analysis panel). Same reparent/repaint family.
- **Fix:** remember and restore the original tab index on re-dock; force a proper reparent + repaint of the detached panel so its content (esp. tool panels) shows immediately and stays rendered while floating.
- **Verify:** detach the Ghidra/Frida/Cutter panel → its controls/content render immediately in the floating window; re-dock → tab returns to its original position with content intact.

### - [x] Export Analysis serializes nested objects as Python repr strings

- **Files:** `src/intellicrack/ui/app.py:1949` (`_on_export_analysis`, `json.dump(..., default=str)`).
- **Problem:** sections etc. export as `"SectionInfo(name='.text', …)"` strings instead of structured JSON.
- **Fix:** give `SectionInfo` (and peers) a `to_dict`/`asdict` and serialize proper nested JSON.
- **Verify:** `analysis_export.json` sections are JSON objects with typed fields.

### - [x] Minor UI glitches: duplicate Analysis tabs; premature "Session import failed" status

- **Problem:** loading a binary can open two "Analysis" tabs; Import shows a transient "Session import failed" status while the replace-confirm dialog is still open.
- **Fix:** dedupe Analysis-tab creation; only set import success/failure status **after** the confirm dialog resolves.
- **Verify:** single Analysis tab per load; no false "failed" flash during import.

### - [x] Branding: "IntelliCrack" → "Intellicrack" (prior UX #4, still open)

- **Problem:** the **splash screen** and the **About dialog logo** read "IntelliCrack" (capital C) while the window title/body use "Intellicrack."
- **Fix:** change the splash and About logo text to "Intellicrack."
- **Verify:** splash + About read "Intellicrack."

### - [x] Prior UX #3 residual — model combo field end-truncation (cosmetic)

- **Problem:** the model **dropdown popup** is fixed, but the combo **field** still end-truncates the selected model id (e.g. `gemini-3.5-fla…`).
- **Fix:** widen the combo or elide with a tooltip showing the full id.
- **Verify:** selected model id readable or hover-tooltip shows full id.

---

## Verify-only (likely non-issues; confirm, don't over-fix)

### - [x] Prior UX #5 — menu-bar click-to-switch quirk

- Earlier "menu won't open" behavior was traced to the **F13** input-drop (the File menu opened normally on a later relaunch). After F13 is fixed, confirm menus open reliably. Do **not** treat as a separate menu defect unless it reproduces with F13 fixed.

### - [x] Prior audit "fixed" items — regression-guard

- Model auto-load on startup, provider "Active: <name>" label, and the model-popup width were reported **fixed** in the functionality audit. Add/confirm a lightweight test so they don't regress; no code change expected.

---

## Deferred verification — DRIVEN LIVE in Phase 3 (2026-07-05)

These needed a spawned target process or a Windows Sandbox VM. **All were driven live on 2026-07-05** (see `audit/Intellicrack_GUI_DeepFunctional_Audit_Phase3_2026-07-05.md`); results and follow-up tasks are inline below. Summary: **Frida works**; **Ghidra** and **x64dbg** are broken at the bridge layer (new tasks **F15**/**F16**); **Sandbox** is blocked by a host Hyper-V/HCS problem (not an app bug); Cancel/edge cases produced **F17** + the **F11 residual**. **Tooling is installed** (from `logs/intellicrack.log` `tool_found`/version events): Ghidra **12.1.2** at `C:\Tools\ghidra\support\analyzeHeadless.bat` (headless is the analysis path — expect Ghidra Analyze to require **Start Headless**); x64dbg **2026.05.27** at `C:\Tools\x64dbg\release\x64\x64dbg.exe`; Cutter backend rizin **0.9.1**; Frida reported installed in the prior audit. Windows Sandbox was detected as available.

- [x] **Ghidra** — obtain real decompiled/disassembly output. **Status:** Driven live 2026-07-05 (Start Headless + in-panel Load Binary, both orders, ~40 s + Refresh). **Still broken — root-caused as new task F15** (`ghidra_bridge` RPC `_execute_remote` times out; `GhidraBridge` built with no `response_timeout`). Decompiled/Functions/Strings stay empty. Fix F15 to close.
- [x] **x64dbg** — start a debug session, set a breakpoint, step; verify registers/state update. **Status:** Driven live 2026-07-05. **Still broken — root-caused as new task F16** (bridge-plugin named pipe `\\.\pipe\intellicrack_x64dbg` never comes up; standalone x64dbg.exe launches by design but Step Into fails, Registers/Disassembly empty). Fix F16 to close.
- [x] **Frida** — attach to a spawned process and land a hook; watch Console Output. **Status:** VERIFIED WORKING 2026-07-05 — Spawn (PID captured) → Attach → script injection → `Interceptor.attach(ntdll!NtCreateFile)` → Resume → `[send] [hook] NtCreateFile fired` streamed live. Closed. (Minor: after Run Script the button disables — must Detach to swap scripts; script-installed hooks don't show in the Active Hooks table.)
- [x] **Sandbox** — "Run in Sandbox" a benign binary; capture the report tabs. **Status:** Driven live 2026-07-05 (Create → run notepad.exe). **Blocked by HOST, not the app:** Windows Sandbox could not start — `0x800706d9 EPT_S_NOT_REGISTERED` (Hyper-V/Host-Compute-Service endpoints not registered). App diagnosed it correctly (positive finding). **Report tabs not captured — re-run after repairing the host** (restart `hns`/`vmcompute`/`WinNat` or reboot).
- [x] **Cancel button / rapid actions / malformed / large binary.** **Status:** Driven live 2026-07-05. **Cancel works** (aborts in-flight chat, returns to idle) but leaves a lingering cancelled state → **new task F17** (following actions throw "async operation cancelled"). **Large 300 MB binary** loads with no UI hang. **Second-binary-over-first** updates cleanly (no stale data). **Malformed/truncated PE** loads as `Format: unknown` with no invalid-format warning and tools still enabled (residual half of **F11**). Rapid tool-panel burst was stable apart from surfacing F17.

---

## Phase 3 new tasks (2026-07-05) — quick index

- **F15** (P0) — Ghidra `ghidra_bridge` RPC timeout → empty Analyze output.
- **F16** (P0) — x64dbg bridge-plugin named pipe never comes up → panel inert.
- **F17** (P1) — Cancel leaves stale `_cancel_event` → spurious "async operation cancelled" modals.
- **F18** (P2, folded into F3) — detached tool panel renders a blank body.
- **F11 residual** (P1) — malformed/unknown-format load: no invalid-format feedback; tools stay enabled.

> **Logging note (corrected 2026-07-05):** an earlier Phase 3 draft claimed the running instance "wasn't writing to `intellicrack.log`." **That was wrong** — the app logs fine. The confusion was that `D:\Intellicrack\logs\intellicrack.log` (the repo copy) is a **stale, divergent** file; the live app writes its real `intellicrack.log` to the resolved log dir (`Config.logs_directory`, else `Path.cwd()/logs` — `core/logging.py:47-68`). The real log (16,202 lines, 17:02→19:38:51, `handlers_installed` at 18:19:25 for the tested instance) **corroborates every Phase 3 finding**: 38× Ghidra `Remote execution failed: timed out` (F15), 179 x64dbg pipe/plugin events (F16), `sandbox_auto_start_failed 0x800706d9` at `sandbox/manager.py:329`, and **21× `GenericCallableWorker has been deleted` + 62× `async_bridge_worker_failed`** (F13 still active). Prior Phase 2 "last-writer-wins / not logging" caveats should be read in this light: the app logs; the **repo `logs/` copy can go stale** because it isn't the live target. (Optional cleanup task: make the resolved log dir unambiguous / avoid a stale `logs/intellicrack.log` sitting in the repo tree.)
