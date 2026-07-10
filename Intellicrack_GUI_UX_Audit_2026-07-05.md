# Intellicrack GUI / UX Audit

**Date:** 2026-07-05
**Build:** Intellicrack 0.1.0a1 (per About dialog)
**Method:** Live desktop control of the running GUI (screenshots + synthetic mouse/keyboard), driving menus, dialogs, toolbar controls, and edge cases.

---

## Important methodology caveats (read first)

The audit environment materially affected input, and two of these points invalidate "bugs" that a naive sweep would have reported:

- **The app was initially running elevated (as administrator).** While elevated, Windows UIPI silently blocked *all* synthetic mouse and keyboard input from the automation layer — clicks, typing, menu opens, dialogs: nothing registered. Screenshots still worked. After relaunching Intellicrack **non-elevated**, input reached the app normally.
- **The session ran over Parsec (remote desktop), which corrupts per-keystroke synthetic input.** Demonstrated on plain Notepad: typing `test 123` produced `33333333` (same length, characters mangled). The clipboard-paste input path is unaffected and types cleanly, so all text-entry tests here used that path. Anyone re-running UI automation over Parsec should expect unreliable per-key input.
- **Two early "findings" were environment artifacts, NOT real bugs** — verified false once the app was running healthy (non-elevated):
  - *"Chat message input is cramped into a narrow ~150px column with truncated placeholder."* → The healthy instance shows a correct full-width input with a **Send** button. False positive from the broken elevated instance.
  - *"Menu bar doesn't open on click."* → Purely the UIPI input block. All menus open and function normally when non-elevated.

---

## Confirmed findings

### 1. Model dropdown is empty on startup (models not auto-loaded) — **Medium**

On a fresh launch, the toolbar **Model** dropdown is blank and its list is empty, even though a provider (Anthropic) is selected and the status bar reports `Discovery: 8/8 providers OK`. Models only appear after the user manually runs **Providers → Refresh Models** (status bar then shows `Found 10 models` and the field auto-fills, e.g. `claude-fable-5`).

- **Repro:** Launch app → observe empty Model field → open the Model dropdown (empty) → Providers → Refresh Models → list now populates.
- **Impact:** The empty field reads as "broken" to a new user and the app can't be used for chat until models are manually refreshed.
- **Recommendation:** Auto-refresh the model list on startup and whenever the provider changes.

### 2. "Active: None selected" contradicts the active provider — **Low–Medium**

In **Providers → Configure Providers** (Provider Settings dialog), the footer reads **"Active: None selected"** even though Anthropic is highlighted in the list, all 8 providers show green/available, and the main toolbar is operating with Provider = Anthropic (10 models loaded, Test Connection passes).

- **Impact:** State/labeling inconsistency — either the dialog isn't reflecting the currently-used provider, or there are two disconnected notions of "active" vs "selected provider" that will confuse users (there is a separate **Set Active** button).
- **Recommendation:** Show the in-use provider as active, or relabel to make the distinction explicit.

### 3. Model names truncated in the selector — **Low (visual)**

The Model dropdown popup is too narrow, so model IDs are elided **mid-string** and become hard to tell apart, e.g. `claude...us-4-6`, `claude...us-4-7`, `claude...us-4-8`, `claude...et-4-6`, `claude...nnet-5`, `claude...250929`. The combo field itself also clips the leading characters (shows `aude-fable-5` instead of `claude-fable-5`).

- **Recommendation:** Widen the combo and/or set a minimum popup width to fit the longest model ID; prefer end-truncation over mid-truncation if space is constrained.

### 4. Branding capitalization inconsistency — **Cosmetic**

The **About** dialog logo reads **"IntelliCrack"** (capital C) while the window title bar and app name are **"Intellicrack"** (lowercase c). Pick one and apply consistently.

### 5. Menu-bar click-to-switch quirk — **Low (needs manual confirmation)**

With one top-level menu open, *clicking* an adjacent menu title closes the first menu rather than switching to the new one (a second click is needed to open it). Note: *hovering* to switch menus works normally. This may be an artifact of synthetic-input timing rather than a genuine defect — worth a quick manual check with a real mouse before treating it as a bug.

---

## Areas verified working (no issues found)

- **Menus:** All seven top-level menus (File, View, Tools, Providers, Sandbox, Settings, Help) and the **Tools → Embedded Tools** submenu render correctly and open/function.
- **Dialogs (layout & content clean):**
  - **Preferences** — General, Appearance, Session, Logging tabs; consistent grouping, aligned fields, OK/Cancel/Apply.
  - **About** — clean (aside from the capitalization note above).
  - **Provider Settings** — rich, well-organized (provider list with status dots, masked API key + Show, source indicator, connection settings, Test Connection, resource links).
  - **Tool Status & Capabilities** — clean; per-tool capability dots, architectures, formats.
- **Toolbar toggles:** **Auto-approve** and **Sandbox** toggle correctly with clear status-bar confirmation messages.
- **Providers → Refresh Models:** works (`Found 10 models`).
- **Empty Send:** clicking **Send** with an empty input is correctly ignored — no blank message, no error.
- **Disabled state:** the toolbar tool buttons (x64dbg, Cutter, Hex Editor, Ghidra, Frida) are greyed out while no binary is loaded — expected/correct.
- **Layout:** toolbar and three-panel layout (Chat / Analysis Output / Functions + Cross References) hold together at maximized, restored near-full, and ~half-screen widths.

---

## Suggested priority order

1. Auto-load models on startup / provider change (Finding 1) — biggest first-run "looks broken" issue.
2. Reconcile the "Active: None selected" provider state/labeling (Finding 2).
3. Widen the model selector to stop mid-string truncation (Finding 3).
4. Fix the About-logo capitalization (Finding 4).
5. Manually confirm the menu click-to-switch behavior (Finding 5).
