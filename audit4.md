> # Audit List 4/6
>
> Drive **every F-#### finding below** to production release-ready. For
> each finding: re-verify against the cited source/lines, implement the
> full fix per the `Suggested remediation summary`, and write
> production-grade tests that fail without the fix and pass with it. If a
> finding is already resolved on `main`, annotate it in this file by
> appending `[obsolete: <commit-hash>]` to the F-#### heading line (e.g.
> `#### F-0042 [obsolete: c0bfbdf9] - <original title>`) and move on.
>
> ## Orchestrator Responsibility (Claude)
>
> **Claude bears final, non-delegable responsibility for verifying that
> every fix is a real, root-cause solution — never a workaround,
> monkeypatch, or band-aid that masks the underlying defect.** Reject any
> change that:
>
> - Suppresses, hides, or routes around the failure mode instead of fixing
>   the cause described in `Why this is non-functional`.
> - Adds opt-in flags or "preserve old behavior" toggles that leave the
>   broken code path reachable.
> - Catches and swallows the symptom (logging-only, fake `success: True`,
>   silent fallback, bare `except`) instead of correcting the logic.
> - Replaces one fake-success path with a different fake-success path.
> - Disables, weakens, skips, or `xfail`s tests / assertions to silence a
>   failure.
> - Adds shim layers, polyfills, or compatibility wrappers when the
>   upstream call site or data structure should be corrected directly.
> - Inserts `type: ignore`, `pyright: ignore`, `noqa`, or other
>   suppression directives instead of fixing the actual defect.
> - Hardcodes a value, sentinel, or "known-good" response in place of the
>   real computation.
> - Monkeypatches at runtime or vendors a private copy of upstream code to
>   avoid touching the real broken site.
>
> Do not mark a finding resolved until the underlying defect is
> **actually** gone and the new tests would have caught the original bug.
>
> Hard constraints:
>
> - Production-ready and immediately deployable; zero placeholders, mocks,
>   stubs, simulated implementations, or fake-success returns.
> - `ruff check` clean, fully `basedpyright` compliant, `pydoclint` and
>   `pydocstyle` clean — no inline suppression directives of any kind.
> - Windows-first compatibility, preserve existing functionality, never
>   delete a method binding — implement the missing function instead.
> - Every F-#### below must end fixed-and-tested or annotated
>   `[obsolete: <commit-hash>]` inline on its heading line in this file.
>
> ---

# Findings: sandbox-py

## Files audited (8)

- src/intellicrack/sandbox/**init**.py
- src/intellicrack/sandbox/_log_helpers.py
- src/intellicrack/sandbox/_log_parsers.py
- src/intellicrack/sandbox/analysis.py
- src/intellicrack/sandbox/base.py
- src/intellicrack/sandbox/manager.py
- src/intellicrack/sandbox/qemu.py
- src/intellicrack/sandbox/windows.py

## Findings

### Category 7 - Concurrency Issues

#### F-0001 - `SandboxManager.create()` deadlocks on capacity eviction

- **File:** `src/intellicrack/sandbox/manager.py`
- **Lines:** 184-192
- **Pattern:** Cat 7
- **Why this is non-functional:** `SandboxManager.create()` acquires `self._lock`. Inside the critical section, when at capacity it calls `await self.destroy(oldest.id)`. `destroy()` also does `async with self._lock:` to take the same lock. `asyncio.Lock` is not reentrant, so the second acquisition blocks indefinitely.

### Category 1 - Empty / Stub Implementations

#### F-0002 - `QEMUSandbox.start()` instantiates `GuestAgentClient` but never calls `connect`

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1311 + 1949-1994
- **Pattern:** Cat 1
- **Why this is non-functional:** `GuestAgentClient.is_connected` is permanently `False` for the lifetime of the sandbox. Every code path guarded by `self._agent.is_connected` is dead. The "fallback" path in `run_command` writes a script to `<shared>/input/exec_*.cmd` and polls `<shared>/output/result_*.txt`, but nothing in the guest watches the input folder.

### Category 4 - Wrong Field Returned

#### F-0003 - `_poll_for_result` returns hardcoded empty stdout/stderr

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2042-2076
- **Pattern:** Cat 4

### Category 15 - Windows Compatibility

#### F-0004 - `-cpu host` requires hardware virtualisation; broken with TCG fallback

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1119-1132
- **Pattern:** Cat 15, Cat 21

#### F-0005 - SMB shared folder unavailable on Windows-host QEMU; 9p unsupported

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1158-1170
- **Pattern:** Cat 15

### Category 1 - Empty / Stub

#### F-0006 - No mechanism to start the guest agent script

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1608-1947
- **Pattern:** Cat 1, Cat 9
- **Why this is non-functional:** `start_agent.cmd` and `start_agent.sh` are written into the shared folder, but nothing in the QEMU launch ever arranges for the guest to execute them.

### Category 4 - Wrong Implementation

#### F-0007 - extract_dropped_files won't work if agent disconnected, allowlist mismatch otherwise

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2710-2717
- **Pattern:** Cat 4, Cat 14

### Category 21 - Wrong PowerShell Construct

#### F-0008 - `_file_monitor_source` uses `$using:` which is invalid in `Register-ObjectEvent -Action`

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 862-877
- **Pattern:** Cat 21
- **Why this is non-functional:** `$using:logPath` is only valid in `Invoke-Command`, `ForEach-Object -Parallel`, or other runspace-bound script blocks. The action terminates immediately and never writes to `file_monitor.log`.

#### F-0009 - QEMU agent script same `$using:` defect

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1457-1468
- **Pattern:** Cat 21

### Category 13 - Heuristic Mismatch

#### F-0010 - `_resolve_worker_pid` heuristic doesn't match docstring

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 469-533
- **Pattern:** Cat 13, Cat 21

### Category 21 - Wrong Attribute Name

#### F-0011 - `time_limit` vs `timeout_seconds` mismatch

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 132-149
- **Pattern:** Cat 21

### Category 4 - Wrong Format / Return Contract

#### F-0012 - `pktmon` writes ETL not PCAP

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1295-1363
- **Pattern:** Cat 4

### Category 4 - Cosmetic, Ineffective

#### F-0013 - `apply_anti_evasion` patches volatile registry hive

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1417-1510
- **Pattern:** Cat 4

### Category 18 - Resource Leak

#### F-0014 - `_cleanup` shutil.rmtree silently swallows errors

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 535-550
- **Pattern:** Cat 18, Cat 6

### Category 11 - Redundant Work / Side Effects

#### F-0015 - `start()` redoes accelerator detection

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1226-1322
- **Pattern:** Cat 11, Cat 14

### Category 21 - Wrong Success Condition

#### F-0016 - `_detect_accelerator` reports WHPX available on Hyper-V-disabled hosts

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 944-995
- **Pattern:** Cat 21

### Category 14 - Silent Error Swallowing

#### F-0017 - `_dispatcher_ps1_source` catch swallows all errors

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 685-734
- **Pattern:** Cat 14

### Category 21 - Fragile PowerShell

#### F-0018 - `_process_monitor_source` uses `$pid` automatic variable

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1011-1049
- **Pattern:** Cat 21

#### F-0019 - `_registry_monitor_source` hardcoded REG_SZ + unapproved verb

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 883-954
- **Pattern:** Cat 4, Cat 21

### Category 4 - Effectively No-Op

#### F-0020 - `extract_dropped_files` ignores xcopy exit codes

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1627-1688
- **Pattern:** Cat 4, Cat 18

### Category 21 - Targets PPL

#### F-0021 - `dump_memory` cannot succeed against vmwp.exe

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1512-1588 + 1890-1968
- **Pattern:** Cat 21, Cat 4

### Category 21 - Allowlist Mismatch

#### F-0022 - QEMU `apply_anti_evasion` uses `reg.exe` blocked by guest agent allowlist

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2536-2620
- **Pattern:** Cat 21

### Category 4 - Wrong Parser

#### F-0023 - `list_snapshots` parses QMP response incorrectly

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2298-2318
- **Pattern:** Cat 4

### Category 18 - Resource Leak

#### F-0024 - `get_available_types` triggers expensive subprocesses on every call

- **File:** `src/intellicrack/sandbox/manager.py`
- **Lines:** 130-146
- **Pattern:** Cat 18

#### F-0025 - `stop` does not clean active captures

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 820-822 + 1324-1364
- **Pattern:** Cat 18

### Category 4 - Over-Broad Pattern

#### F-0026 - `_DOMAIN_PATTERN` matches `.dll`, `.exe`, etc

- **File:** `src/intellicrack/sandbox/analysis.py`
- **Lines:** 38-41
- **Pattern:** Cat 4, Cat 23

### Category 4 - Wrong Source Set

#### F-0027 - `yara_scan` falls back to scanning user input

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1693-1780
- **Pattern:** Cat 4

#### F-0028 - QEMU `yara_scan` same defect

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2810-2828
- **Pattern:** Cat 4

### Category 21 - Profile Selected But Ignored

#### F-0029 - QEMU `apply_anti_evasion(profile=...)` ignores profile parameter

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2502-2625
- **Pattern:** Cat 21

### Category 13 - Race Condition / Fixed Sleep

#### F-0030 - Windows `run_binary` 3-second sleep

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1191-1232
- **Pattern:** Cat 13

#### F-0031 - QEMU `run_binary` 2-second sleep

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2152-2156
- **Pattern:** Cat 13

### Category 11 - Spawns Subprocess Every Call

#### F-0032 - `WindowsSandbox.is_available` invokes Get-WindowsOptionalFeature on every call

- **File:** `src/intellicrack/sandbox/manager.py`
- **Lines:** 130-146
- **Pattern:** Cat 11

### Category 18 - Disk Leak

#### F-0033 - `run_command` ticket files never deleted

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1083-1105
- **Pattern:** Cat 18

### Category 4 - Wrong Result Label

#### F-0034 - Windows `run_binary` always reports "success" regardless of exit_code

- **File:** `src/intellicrack/sandbox/windows.py`
- **Lines:** 1107-1195
- **Pattern:** Cat 4

#### F-0035 - QEMU `run_binary` same defect

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2078-2174
- **Pattern:** Cat 4

# Findings: ui-panels-process

## Files audited (8)

- src/intellicrack/ui/panels/process_panel/**init**.py
- src/intellicrack/ui/panels/process_panel/_base.py
- src/intellicrack/ui/panels/process_panel/_process_tab.py
- src/intellicrack/ui/panels/process_panel/_memory_tab.py
- src/intellicrack/ui/panels/process_panel/_threads_tab.py
- src/intellicrack/ui/panels/process_panel/_modules_tab.py
- src/intellicrack/ui/panels/process_panel/_system_tab.py
- src/intellicrack/ui/panels/process_panel/_workers.py

## Summary

Nearly every button on every tab dispatches an awaitable `ProcessBridge.*` coroutine through `run_bridge_coroutine_async`, and the bridge methods call real Win32 APIs. The critical attach/suspend/memory r/w/thread enum/DLL inject/handle enum paths all round-trip to real kernel calls. 26 functional gaps where panel state is fabricated, displayed-only, or ignored, and where bridge errors are swallowed silently.

## Findings

### Category 18 - GUI / UX Wiring Failures

#### F-0001 - `_status_arch` label is permanently `"Arch: --"` — never updated from the bridge

- **File:** `src/intellicrack/ui/panels/process_panel/_base.py`
- **Lines:** 195-249
- **Pattern:** Cat 18

#### F-0002 - `_status_priv` privilege label depends on a private bridge attribute that is never refreshed after a privilege change

- **File:** `src/intellicrack/ui/panels/process_panel/_base.py`
- **Lines:** 199-272
- **Pattern:** Cat 18

#### F-0003 - `MemoryTab._region_filter` filter input is never connected to anything

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 116-120, 365-392
- **Pattern:** Cat 18

#### F-0004 - `ModulesTab._mod_filter` filter input is never connected to anything

- **File:** `src/intellicrack/ui/panels/process_panel/_modules_tab.py`
- **Lines:** 118-122, 279-310
- **Pattern:** Cat 18

#### F-0005 - Memory tab actions are not gated on attachment — silent no-ops with no user feedback when not attached

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 49-95, 365-588
- **Pattern:** Cat 18

#### F-0006 - `MemoryTab._on_search` "Searching..." status never resets on failure

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 563-587
- **Pattern:** Cat 18

#### F-0007 - `MemoryTab._on_free` adds a new "Freed" row instead of removing the corresponding "Allocated" row

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 496-526
- **Pattern:** Cat 11

#### F-0008 - `_on_protect` and `_on_free` parse errors are logged but not surfaced

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 496-561
- **Pattern:** Cat 18

#### F-0009 - `MemoryTab._build_protect_tab` lacks a placeholder hint for the address field

- **File:** `src/intellicrack/ui/panels/process_panel/_memory_tab.py`
- **Lines:** 293-297
- **Pattern:** Cat 18

#### F-0010 - `ThreadsTab._on_suspend_thread` / `_on_resume_thread` mislabeled — they suspend the entire process

- **File:** `src/intellicrack/ui/panels/process_panel/_threads_tab.py`
- **Lines:** 142-152, 386-396
- **Pattern:** Cat 18

#### F-0011 - `ThreadsTab._on_tls` reads the TID from the Fiber combo, not its own selector

- **File:** `src/intellicrack/ui/panels/process_panel/_threads_tab.py`
- **Lines:** 286-333, 544-570
- **Pattern:** Cat 18

#### F-0012 - `ThreadsTab` thread combos only update on explicit Refresh

- **File:** `src/intellicrack/ui/panels/process_panel/_threads_tab.py`
- **Lines:** 96-106, 353-384
- **Pattern:** Cat 11

#### F-0013 - `ProcessTab._inject_btn` does not require attachment and gives no feedback on failure or success

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 202-205, 501-523
- **Pattern:** Cat 18

#### F-0014 - `ProcessTab._on_filter_changed` fires a full bridge round-trip on every keystroke

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 153-158, 395-401
- **Pattern:** Cat 4

#### F-0015 - `ProcessTab._on_attach` does not surface failure

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 434-453
- **Pattern:** Cat 5

#### F-0016 - `ProcessTab._on_suspend`, `_on_resume`, `_on_terminate`, and `_load_process_info` silently consume bridge errors

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 465-549
- **Pattern:** Cat 5

#### F-0017 - `ProcessTab._on_terminate` only refreshes the system list, not the Tracked sub-tab

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 477-499
- **Pattern:** Cat 11

#### F-0018 - `ProcessTab._on_terminate` does not detach the panel state if the terminated PID is currently attached

- **File:** `src/intellicrack/ui/panels/process_panel/_process_tab.py`
- **Lines:** 477-499
- **Pattern:** Cat 11

#### F-0019 - `ThreadsTab._on_write_registers` reads only the Hex column — Decimal-column edits are silently dropped

- **File:** `src/intellicrack/ui/panels/process_panel/_threads_tab.py`
- **Lines:** 421-457
- **Pattern:** Cat 18

#### F-0020 - `SystemTab._on_pipe_close` removes the row before knowing whether the close succeeded

- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Lines:** 626-644
- **Pattern:** Cat 11, Cat 5

#### F-0021 - `SystemTab._on_job_info` appends to `_res_tree` instead of clearing it

- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Lines:** 727-764
- **Pattern:** Cat 18

#### F-0022 - `SystemTab` privileges, debug-enable, services, and PEB read ignore `_attached_pid is None`

- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Lines:** 472-587
- **Pattern:** Cat 18
- **Why this is non-functional:** `get_token_privileges(None)` and `adjust_token_privilege(..., pid=None)` operate on Intellicrack's own process when nothing is attached. The user sees a populated table and assumes it represents the target.

#### F-0023 - SystemTab queries swallow bridge errors silently

- **File:** `src/intellicrack/ui/panels/process_panel/_system_tab.py`
- **Lines:** 472-790
- **Pattern:** Cat 5

#### F-0024 - ModulesTab refreshes (handles, heaps, COM, .NET) all swallow bridge errors

- **File:** `src/intellicrack/ui/panels/process_panel/_modules_tab.py`
- **Lines:** 353-446
- **Pattern:** Cat 5

#### F-0025 - `_base._update_controls_for_state` enables/disables tab widgets but never enables/disables Process tab buttons

- **File:** `src/intellicrack/ui/panels/process_panel/_base.py`
- **Lines:** 158-272
- **Pattern:** Cat 18

#### F-0026 - `_workers.TrackedRefreshWorker` swallows all errors and emits an empty list

- **File:** `src/intellicrack/ui/panels/process_panel/_workers.py`
- **Lines:** 47-69
- **Pattern:** Cat 5

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

# Findings: config-pyproject

## Files audited (1)

- `pyproject.toml`

## Findings

### Category 23 - Build Metadata Lies

#### F-0001 - `pyproject.toml` redundantly declares 95+ dev/test/docs/profile packages as runtime `dependencies`

- **File:** `pyproject.toml:43-154`
- **Pattern:** Cat 23, Cat 12
- **Why non-factual:** `pip install intellicrack` pulls pytest, mypy, bandit, basedpyright, ruff, sphinx, mkdocs-material, pre-commit, tox, nox, twine, monkeytype, pyannotate, safety, commitizen, bumpversion as runtime requirements. These are development-time tooling packages that have no business in the published distribution's `[project].dependencies` list — they belong in `[dependency-groups]` / `[project.optional-dependencies]` extras (`dev`, `test`, `docs`, `profile`) instead.
- **Suggested remediation summary:** Move every dev/test/docs/profile-only package from `[project].dependencies` into the appropriate `[dependency-groups]` table (`dev`, `test`, `docs`, `profile`) so that `pip install intellicrack` only pulls genuine runtime requirements. Verify against the existing pixi feature/environment layout in `pyproject.toml` to keep tool resolution consistent.
