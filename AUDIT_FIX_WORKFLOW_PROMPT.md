# Prompt: Intellicrack — Remediate the Phase-4 Backlog (phased, 3 Sonnet-5 agents at a time)

Copy everything below the line into a new Claude session with the `D:\Intellicrack` folder connected.

---

You are the **orchestrator** for a code-remediation effort on **Intellicrack** (a PyQt desktop app at `D:\Intellicrack` that bridges binary-analysis tools — Ghidra, x64dbg, Frida, Cutter, a hex editor, a process inspector, a Windows-Sandbox/QEMU runner — with AI providers). Your job is to drive every open task in `D:\Intellicrack\AUDIT_FIX_TASKS.md` to a **real, tested fix**, by dispatching **sub-agents that run on Sonnet 5**, in **phases of exactly 3 agents at a time**.

Authoritative inputs (read both before doing anything):
- `D:\Intellicrack\AUDIT_FIX_TASKS.md` — the open backlog. Each task is self-contained: **Problem → Root cause (file:line) → Fix steps → Verify**. This file is "open work only": a task present = still open; when a task is verifiably fixed, it is **deleted** from the file.
- `D:\Intellicrack\audit\Intellicrack_GUI_DeepFunctional_Audit_Phase4_2026-07-10.md` — the audit report with the live evidence and root causes behind each task.
- `D:\Intellicrack\CLAUDE.md` — non-negotiable engineering rules (below).

## The single hardest constraint — read first

**Never run more than 3 sub-agents concurrently.** Token and context limits fill up fast. You dispatch a **batch of exactly 3** agents (one message, 3 parallel `Agent` calls), then **wait for all 3 to finish and pass their gates before dispatching the next batch**. Do not queue a 4th while 3 are running. Do not dispatch the next phase until the current phase is fully green and merged.

Keep **your own** context lean: you are an orchestrator, not a coder. Do **not** implement fixes yourself, do not read large source files into your context, and do not paste agent transcripts back into chat. Each agent returns only a short structured result (see "Agent contract"); you keep the conclusion, not the file dumps.

## Engineering rules (from CLAUDE.md — enforce on every agent, non-negotiable)

- Full type hints/annotations everywhere; **`ruff check` clean**; **fully basedpyright-clean**; **`pydoclint` + `pydocstyle` clean**; Google-style docstrings.
- **No suppressions of any kind** (no `type: ignore`, `pyright: ignore`, `noqa` for type/lint/doc issues). Fix the real error. **Never edit or weaken** the locked `[tool.basedpyright]` / ruff / pydoclint / pydocstyle configs.
- **No stubs, mocks, placeholders, TODOs, or example-only implementations.** Production-ready code only. Never delete a method binding to "fix" a type error — implement the missing piece.
- **Windows-first.** Prefer `pwsh` (PowerShell 7); run Python via the pixi env (`pixi run …`, env at `D:\Intellicrack\.pixi\envs\default`).
- **Scope guard:** every change must strengthen Intellicrack's role as a unified GUI bridge for tools/workflows/AI. No malware capabilities.

## Tests must be real, falsifiable gates (this is the point of the whole exercise)

For **every** task, the agent must add or extend a test that is a **true quality gate**:

- Placed under the matching `tests/` area subdir (`test_bridges/`, `test_core/`, `test_providers/`, `test_ui/`) — never at repo root or beside source.
- Exercises the **real behavior** with real inputs (real binaries, real data formats, real bridge/protocol framing). **No asserting on mocks/stubs** in place of the behavior under test. No tautological/always-green tests. No blanket `try/except: pass`, no unconditional `pytest.skip`, no broad exception swallowing that hides a failure.
- **Falsifiability check is mandatory and is part of "done":** after the fix + test land green, the responsible agent must **temporarily revert the production fix** (or apply a one-line mutation that reintroduces the bug), run the test, and **confirm it goes RED**, then restore the fix and confirm GREEN again. The agent reports both outcomes. A test that stays green with the fix reverted is not a gate and must be rewritten.
- **Run tests in the Docker sandbox, never on the host** (this repo's standing convention). Report the exact command and the pass/fail counts.

## Orchestration protocol (repeat per phase)

1. **Plan the batch.** Take the next phase's 3 work-items. Confirm they touch **non-overlapping files** (they are grouped that way on purpose). Re-read the relevant tasks in `AUDIT_FIX_TASKS.md` to hand each agent its exact task text.
2. **Dispatch 3 Sonnet-5 agents in ONE message** (3 parallel `Agent` tool calls). For each: `model: "sonnet"`, `isolation: "worktree"` (each agent works in its own git worktree so parallel edits can't collide), and a prompt that includes: the task's Problem/Root-cause/Fix-steps/Verify verbatim, the engineering rules, the test+falsifiability requirement, and the **Agent contract** output format below. Tell each agent its allowed file set and to **stay within it**.
3. **Wait for all 3 to return.** Do not start anything else meanwhile.
4. **Gate each result yourself (trust but verify).** For each agent's worktree/branch, run in the sandbox: the new/changed tests, `ruff check`, basedpyright, `pydoclint`/`pydocstyle`. Re-run the agent's **falsifiability check** (revert-the-fix → test RED → restore → GREEN) yourself on at least one test per task. If anything is red, **bounce it back to the same agent** (continue it via its ID with the specific failure) — do not accept partial work.
5. **Merge** the 3 worktrees into the working branch. Because file sets are disjoint within a phase, merges should be clean; resolve any incidental conflicts (shared files like `tests/` scaffolding) yourself.
6. **Update the backlog.** For each task now fixed-and-gated, **delete it from `AUDIT_FIX_TASKS.md`** (absent = done). If an agent proved a task was already not-reproducible, delete it with a one-line note in the final report instead.
7. **Only then** dispatch the next phase's batch of 3.

## Agent contract (what every sub-agent must return — keep it short)

- **Task:** id + one-line summary.
- **Root cause confirmed:** the exact `file:function:line` and mechanism (correct or corrected vs. the backlog's guess).
- **Change summary:** files touched (must be within the assigned set) + what changed, in ≤6 lines.
- **Test:** path + name; what real behavior it asserts; the exact sandbox command to run it.
- **Falsifiability proof:** the mutation used to revert the fix, and the observed **RED** result, then the restored **GREEN** result (paste the 2 relevant pytest summary lines).
- **Lint/type gates:** ruff / basedpyright / pydoclint / pydocstyle all clean (paste the summary lines).
- **Do NOT** paste full diffs or file contents; the orchestrator will inspect the worktree.

## Phase plan (3 agents per phase, non-overlapping file sets, dependency-ordered)

Line numbers in the backlog drift — each agent confirms the symbol before editing. If any single agent's scope is genuinely too large for one Sonnet-5 context, it may split its own work internally but must still return one consolidated result; you still never have more than 3 agents live.

### Phase 1 — P0 blockers + their tightest neighbors (no cross-file overlap)

- **Agent 1A — F16 (x64dbg control pipe wedges) + x64dbg unretrieved-future leak.**
  Files: `src/intellicrack/bridges/named_pipe_client.py`, `src/intellicrack/bridges/x64dbg.py`, `src/x64dbg-plugin/*`. Make the pipe multi-instance or serialize all client I/O over one persistent connection so the panel's register/stack refresh can't collide (error 231); re-listen after a client disconnects; fix reader-loop teardown so a read timeout doesn't kill the pipe (error 121); await/handle the pipe-read futures. Tests under `tests/test_bridges/` asserting: after an initial connect, a step advances RIP and a subsequent op still connects (no 231/121); no unretrieved-future on timeout.
- **Agent 1B — F7 (Cutter/rizin backend answers no commands; binary not propagated).**
  Files: `src/intellicrack/bridges/cutter.py`, `src/intellicrack/ui/panels/cutter_panel.py`. Repair the rizin/rzpipe backend so commands return (probe the live backend, verify the pipe handshake, surface a clear "backend unavailable" state instead of silent 5 s timeouts); auto-propagate the app's active binary into the Cutter bridge. Tests under `tests/test_bridges/` asserting `i`/`afl`/sections return real parsed output within a few seconds against a real PE.
- **Agent 1C — Hex Editor "no document open" + auto-parse race on load.**
  Files: `src/intellicrack/ui/panels/hex_editor/panel.py`, `.../sections.py`, `.../disassembly.py`, `src/intellicrack/bridges/hex_editor.py`, `src/intellicrack/ui/tools.py:open_in_hex_editor` (only the hex-open path). Open the hexcore/bridge document when `load_file` runs so PE-parse / disassembly / VA-mapping ops have a document; gate the sidebar auto-refresh on document-loaded to kill the race. Tests under `tests/test_bridges/` (or `test_ui/`) asserting: after load, `get_pe_sections`/disassemble/VA auto-detect return data and no `operation_failed_no_document_open` fires.

### Phase 2 — depends on Phase 1; provider + ghidra areas

- **Agent 2A — F4 (Function → Cross References populate).** *(depends on 1B being merged)*
  Files: `src/intellicrack/ui/tools.py` (xref bridge selection `_select_static_analysis_bridge` / `populate_xrefs_for_address`). Prefer a **ready/healthy** static-analysis bridge; fall back to Ghidra when Cutter is unavailable/erroring; probe bridge health before selecting. Test under `tests/test_ui/` asserting a function with callers yields non-empty References-TO/FROM even when a Cutter panel is open.
- **Agent 2B — Provider toolbar-refresh cluster: HuggingFace `Bearer` header + Ollama local-endpoint refresh + non-chat default model (OpenAI/Grok).**
  Files: `src/intellicrack/providers/huggingface.py`, `.../ollama.py`, `.../openai.py`, `.../grok.py`, and the toolbar provider-select → model-refresh handler (in `src/intellicrack/ui/app.py` or the provider combo handler — confirm; keep to the provider-refresh code path only). HF: don't build an `Authorization: Bearer` header from an empty token on the refresh path (reuse the connected client's token; Test Connection already finds 100 models). Ollama: refresh against the connected endpoint (cloud when local is down) or fall back to the startup-discovered list; clear message instead of a raw WinError. Default-model: auto-select a **chat-capable** model per provider (filter out video/image/audio/moderation models). Tests under `tests/test_providers/` asserting: HF refresh builds a valid header (or none) when token empty/present; Ollama refresh uses the reachable endpoint; auto-select returns a chat model for OpenAI/Grok.
- **Agent 2C — Ghidra: in-panel Load before Start-Headless fails with WinError 10061.**
  Files: `src/intellicrack/bridges/ghidra.py`, `src/intellicrack/ui/panels/ghidra_panel.py`. Gate Load Binary on a ready headless bridge (disabled-with-tooltip until started) or auto-start headless on Load; surface a clear "start headless first" message instead of the raw WinError. Test under `tests/test_bridges/` asserting Load-before-headless yields the gated/clear path, and Start-Headless→Load→Analyze still works.

### Phase 3 — UI/cosmetic + process + the "needs live verification" trio

- **Agent 3A — Light-theme consistency + branding logo wordmark.**
  Files: `src/intellicrack/ui/resources/theme_manager.py`, `src/intellicrack/ui/dialogs/splash_screen.py`, `src/intellicrack/assets/*` (logo/splash). Apply the theme stylesheet to all panels/docks (analysis dock, hex editor, functions panel, toolbar) — not just the menu bar + chat. Update the About/splash logo wordmark asset from "IntelliCrack" to "Intellicrack" (if the wordmark is baked into an image the agent cannot regenerate, replace it with themed text or a corrected asset and say so explicitly). Tests under `tests/test_ui/` asserting the theme manager styles the major docks and the About/splash text reads "Intellicrack".
- **Agent 3B — Process memory-content read + Threads/Modules auto-refresh + right-hand Functions list not cleared on unload.**
  Files: `src/intellicrack/ui/panels/process_panel/*`, `src/intellicrack/ui/panels/analysis_panel.py`, and the Functions-side-list clear in `src/intellicrack/ui/tools.py` (functions-list widget only — 2A is already merged). Default the memory view to a readable committed region (or module base) so ReadProcessMemory doesn't fail on an unreadable default; auto-populate Threads/Modules on attach/tab-activate; clear the right-hand Functions list (and Cross References) when the Analysis panel is cleared. Tests under `tests/test_ui/` for each.
- **Agent 3C — Verify-then-fix trio: F17 cancel stale state, N2 dock clipping, model-combo field truncation.**
  Files: `src/intellicrack/core/orchestrator.py` (cancel/`_cancel_event`), `src/intellicrack/ui/panels/panel_dock.py` + `src/intellicrack/ui/tools.py` dock sizing (N2), model-combo field in `src/intellicrack/ui/app.py`/toolbar. First determine (via a real test) whether each still reproduces; fix those that do. F17: clear `_cancel_event` + reset state to idle as soon as the cancelled op settles, so a later unrelated async op doesn't raise `CancelledError`. N2: sensible min-widths + elide-to-tooltip so docked panels aren't clipped. Combo: widen/elide-with-tooltip so the selected model id is readable. Tests under `tests/test_core/` and `tests/test_ui/` — the F17 test must start an unrelated async op after a cancel and assert it runs (no `CancelledError`).

## Definition of done

- All tasks removed from `AUDIT_FIX_TASKS.md` (file holds only what genuinely remains — ideally empty, or only items proven not-fixable-without-host-changes, e.g. anything gated on the Sandbox host, which is **out of scope** here and must be left with a clear note rather than "fixed").
- Every fix has a real, falsifiable test that you personally watched go RED on revert and GREEN on restore.
- Whole suite + `ruff` + basedpyright + `pydoclint`/`pydocstyle` green in the sandbox on the merged branch.
- A short final report from you: per task — root cause, files, test path, falsifiability proof (RED→GREEN), and gate status. Note explicitly that **live GUI re-verification is a separate follow-up** (a Phase-5 live audit); this workflow delivers code + gated tests, not live-driven confirmation.

## Reminders

- 3 agents max, always. Sonnet 5 (`model: "sonnet"`) for every sub-agent. Worktree isolation for every sub-agent.
- Dependency order matters: **1B (F7) before 2A (F4)**; Phase 1 before Phase 2 before Phase 3.
- Agents stay inside their assigned file set to keep merges clean. You own `AUDIT_FIX_TASKS.md` edits and all merges.
- If an agent's fix would require a locked-config change, a suppression, or a mock-only test, that is a failed result — bounce it back; the constraints are hard.
