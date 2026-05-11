> # Workgroup Directive — Execution Order 12/23: `ui-panels-hex`
>
> Spawn a multi-agent workgroup to drive **every F-#### finding below** to
> production release-ready. The workgroup must run this pipeline for every
> finding in this file:
>
> 1. **`developer`** agents (in parallel where findings touch disjoint
>    files) — implement the full fix per the finding's `Suggested
>    remediation summary`. No placeholders, mocks, stubs, hardcoded
>    returns, or fake-success paths. Re-verify each finding against the
>    cited source/lines before fixing; if already resolved, annotate
>    `[obsolete]` with the resolving commit hash and move on.
> 2. **`code-reviewer`** — verify each fix actually addresses the failure
>    mode described in `Why this is non-functional` and audit every caller
>    listed under `Callers / blast radius` for regressions.
> 3. **`test-writer`** — author production-grade tests that fail without
>    the fix and pass with it. Tests must execute against real binaries,
>    real bridges, and real protocols. No mocks of the unit under test.
> 4. **`test-reviewer`** — confirm tests genuinely validate the fix and
>    meet Intellicrack's no-mock standard.
> 5. **`linter`** — run `ruff check`, `basedpyright`, `pydoclint`, and
>    `pydocstyle`; resolve every finding without suppression directives.
>
> Hard constraints (non-negotiable):
>
> - Production-ready and immediately deployable; zero placeholders, mocks,
>   stubs, simulated implementations, or fake-success returns.
> - `ruff check` clean, fully `basedpyright` compliant, `pydoclint` and
>   `pydocstyle` clean — no inline suppression directives of any kind.
> - Windows-first compatibility, preserve existing functionality, never
>   delete a method binding — implement the missing function instead.
> - When this file is fully processed, every F-#### below must be either
>   fixed-and-tested or annotated `[obsolete]` with the resolving commit.
> - **All work for this file ships as one single PR (one PR per prompt /
>   per file).** Every F-#### in this file must be batched into the same
>   PR — do not split findings across multiple PRs, and do not merge any
>   subset until the whole file is fixed-and-tested or annotated
>   `[obsolete]`.
>
> ---
>
# Findings: ui-panels-hex

## Files audited (24)

All files under `src/intellicrack/ui/panels/hex_editor/`.

## Findings

### Category 18 - GUI / UX Wiring Failures

#### F-0001 - Search is wired to non-existent `self._document`; every search no-ops or raises AttributeError

- **File:** `src/intellicrack/ui/panels/hex_editor/_search.py`
- **Lines:** 245-280, 457-535
- **Pattern:** Cat 18, Cat 8
- **Excerpt:**

  ```python
  def _on_search(self) -> None:
      if self._document is None or self._search_input is None or self._search_mode_combo is None:
          return
      ...
      self._search_worker = GenericCallableWorker(
          execute_text_search,
          self._document,        # always None / AttributeError
          ...
  ```

- **Why this is non-functional:** Every other place stores the document on `self.document`. `self._document` is declared as a class-level annotation but never assigned. Both `_on_search` (Find toolbar/Ctrl+F) and `_on_numeric_search` are dead.

### Category 9 - Bridge Integration

#### F-0002 - Highlight rules update only the local widget, never the bridge

- **File:** `src/intellicrack/ui/panels/hex_editor/_highlighting.py`
- **Lines:** 199-292
- **Pattern:** Cat 9, Cat 18
- **Why this is non-functional:** `HexEditorBridge.add_highlight_rule`/`remove_highlight_rule` produce zero hits in the panel directory. AI assistants asking `hex_editor.list_highlight_rules` get an empty list even after the user has built a stack of rules in the GUI.

### Category 11 - Persistence / State Issues

#### F-0003 - Document mutations skip `state_holder.notify_data_modified` in 5+ mixins

- **Files:** `_bookmarks.py:23-47`, `_data_inspector.py:170-206`, `_transforms.py:508-563, 646-794`, `_templates.py:204-229, 287-491`, `_hashing.py:152-194`
- **Pattern:** Cat 11
- **Why this is non-functional:** Bridge calls `notify_data_modified` after every write/insert/delete/fill/copy/move. Panel does not. AI tool calls inspecting the document after a GUI edit will not be told the bytes changed and will analyse stale state.

#### F-0004 - `_on_selection_changed` selection stored locally only; never propagated to bridge

- **File:** `src/intellicrack/ui/panels/hex_editor/panel.py`
- **Lines:** 865-879
- **Pattern:** Cat 11, Cat 18
- **Why this is non-functional:** When the user drags a selection in the GUI hex view, the bridge's `_selection` is never updated. AI tools/scripts that ask the bridge to act on "the current selection" see empty/stale selection.

### Category 9 - Bridge Bypass

#### F-0005 - `_process_memory.py` bypasses bridge and hard-replaces `self.document` without state holder notification

- **File:** `src/intellicrack/ui/panels/hex_editor/_process_memory.py`
- **Lines:** 282-324
- **Pattern:** Cat 9, Cat 11
- **Why this is non-functional:** Bridge's `open_process_memory(pid, address, size)` would update document, state, and notify state holder. Panel reimplements step (a) only - bridge keeps pointing at previous file and state holder never fires.

#### F-0006 - `_sandbox.py` reimplements docker/qemu/scp/copy logic instead of routing through SandboxBridge

- **File:** `src/intellicrack/ui/panels/hex_editor/_sandbox.py`
- **Lines:** 124-219
- **Pattern:** Cat 9
- **Why this is non-functional:** Panel skips SandboxBridge and shells out to `docker cp`, `scp`, `ssh`, `shutil.copy2` itself with hard-coded container name. Cannot benefit from instance reuse, snapshotting, traffic capture.

#### F-0007 - IPS/BPS/UPS export+import bypass bridge's `export_patches`/`import_patches`

- **File:** `src/intellicrack/ui/panels/hex_editor/_patches.py`
- **Lines:** 157-194, 298-332
- **Pattern:** Cat 9
- **Why this is non-functional:** Bridge's `export_patches(format)` was designed precisely so AI/CLI and the GUI agree on patch wire format and Python-fallback behaviour. Panel calls `document.export_patches_*` directly, missing the bridge's Python fallback.

### Category 20 - Dead Code

#### F-0008 - `_ips.py` entire 285-line module is dead code

- **File:** `src/intellicrack/ui/panels/hex_editor/_ips.py`
- **Lines:** 1-286
- **Pattern:** Cat 20
- **Why this is non-functional:** Project-wide grep returns matches only inside `_ips.py` itself. Patches mixin uses `document.export_patches_ips` directly; bridge uses its own `_build_ips_from_patches`. Code never runs.

### Category 6 - Resource Leak

#### F-0009 - `_comparison.py` snapshot temp file created with `delete=False` and never cleaned up

- **File:** `src/intellicrack/ui/panels/hex_editor/_comparison.py`
- **Lines:** 128-161
- **Pattern:** Cat 6

### Category 11 - State Drift

#### F-0010 - `panel.py` save path stops listening for `DOCUMENT_OPENED` after first file load

- **File:** `src/intellicrack/ui/panels/hex_editor/panel.py`
- **Lines:** 827-863
- **Pattern:** Cat 11
- **Why this is non-functional:** The guard `self.document is None` means once the user opens any file, bridge/CLI/AI calls of `hex_editor.open_file` will fire `DOCUMENT_OPENED` but the panel ignores them.

### Category 9 - Bridge Bypass

#### F-0011 - `_data_inspector._on_encode_text` falls back to a class-level encoder when no doc is open

- **File:** `src/intellicrack/ui/panels/hex_editor/_data_inspector.py`
- **Lines:** 332-376
- **Pattern:** Cat 9

### Category 11 - State Drift

#### F-0012 - Pattern editor and templates mixin partial sync to state holder

- **Files:** `_pattern_editor.py:257-287`, `_templates.py:204-229`
- **Pattern:** Cat 11

### Category 4 - Performance

#### F-0013 - `_disassembly._on_cursor_moved_disasm` triggers full bridge disassemble on every cursor movement

- **File:** `src/intellicrack/ui/panels/hex_editor/_disassembly.py`
- **Lines:** 249-258
- **Pattern:** Cat 4
- **Why this is non-functional:** Holding an arrow key down spams the bridge with hundreds of disassemble calls per second. No debouncing, no in-flight worker guard, no equality check.

### Category 11 - State Drift

#### F-0014 - `_search` results not cleared when changing modes

- **File:** `src/intellicrack/ui/panels/hex_editor/_search.py`
- **Lines:** 290-321, 546-575, 434-455
- **Pattern:** Cat 11

### Category 20 - Dead Code

#### F-0015 - `_highlighting.refresh_pattern_highlights` calls `_hex_widget.update()` twice

- **File:** `src/intellicrack/ui/panels/hex_editor/_highlighting.py`
- **Lines:** 343-349
- **Pattern:** Cat 20

### Category 5 - Error Handling

#### F-0016 - `_data_inspector._update_bit_buttons` returns early on first error and leaves remaining bit buttons stale

- **File:** `src/intellicrack/ui/panels/hex_editor/_data_inspector.py`
- **Lines:** 146-168
- **Pattern:** Cat 5

#### F-0017 - `_pattern_editor._on_pattern_apply` only emits `notify_template_registered` from one of two execution paths

- **File:** `src/intellicrack/ui/panels/hex_editor/_pattern_editor.py`
- **Lines:** 237-331
- **Pattern:** Cat 11

### Category 1 - Stub

#### F-0018 - `_sandbox._do_save` `windows_sandbox` branch ignores `_WDAG_PATH` semantics

- **File:** `src/intellicrack/ui/panels/hex_editor/_sandbox.py`
- **Lines:** 173-176
- **Pattern:** Cat 1
- **Why this is non-functional:** `C:\Users\WDAGUtilityAccount\Desktop` only exists inside the live Windows Sandbox VM, not on the host. Copy will either fail or write somewhere unexpected.

### Category 7 - Concurrency

#### F-0019 - `_sandbox.execute_sandbox_operation` creates new asyncio loop per call

- **File:** `src/intellicrack/ui/panels/hex_editor/_sandbox.py`
- **Lines:** 85-122
- **Pattern:** Cat 7
- **Why this is non-functional:** Spinning a fresh event loop on a worker thread defeats the persistent bridge event loop.

### Category 19 - Data Format

#### F-0020 - `_scripting._DocAPI.search_text` hard-codes UTF-8, ignoring panel's encoding combo

- **File:** `src/intellicrack/ui/panels/hex_editor/_scripting.py`
- **Lines:** 562-573
- **Pattern:** Cat 19

#### F-0021 - `_scripting.execute_script` `print(..., file=...)` lost or crashes

- **File:** `src/intellicrack/ui/panels/hex_editor/_scripting.py`
- **Lines:** 955-973
- **Pattern:** Cat 21

### Category 6 - Resource

#### F-0022 - `_hashing._on_custom_crc` reads entire document into Python memory on UI thread

- **File:** `src/intellicrack/ui/panels/hex_editor/_hashing.py`
- **Lines:** 59-73
- **Pattern:** Cat 6, Cat 4

#### F-0023 - `_signatures._on_scan_signatures` reads full document on UI thread before launching worker

- **File:** `src/intellicrack/ui/panels/hex_editor/_signatures.py`
- **Lines:** 429-463
- **Pattern:** Cat 6, Cat 4

### Category 18 - GUI/UX

#### F-0024 - `panel._do_copy_as` swallows errors silently when no clipboard is available

- **File:** `src/intellicrack/ui/panels/hex_editor/panel.py`
- **Lines:** 995-1008
- **Pattern:** Cat 18
