# Test-Gate Audit — test_audit4 (group 1: sandbox + process/threads/memory tabs)

## Summary
- Files audited: 19 (8 test modules + 5 `__init__.py` + 1 `conftest.py` + 1 shared helper read for context; the loose top-level file is `__init__.py`)
- Test functions examined: 122 (parametrized functions counted once)
- Genuine gates: 109
- Flagged non-gates: 13  (CRITICAL: 0, HIGH: 0, MEDIUM: 9, LOW: 4)

## Coverage checklist
- [x] tests/test_audit4/__init__.py — gates: 0, flagged: 0 (package docstring only; this is the loose top-level .py)
- [x] tests/test_audit4/a1_sandbox_manager_caching/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py — gates: 14, flagged: 0
- [x] tests/test_audit4/a2_sandbox_analysis_regex/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py — gates: 16, flagged: 0
- [x] tests/test_audit4/a3_qemu_sandbox/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py — gates: 27, flagged: 6
- [x] tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py — gates: 6, flagged: 0
- [x] tests/test_audit4/a4_windows_sandbox/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit4/a4_windows_sandbox/test_ps_sources.py — gates: 9, flagged: 7
- [x] tests/test_audit4/b1_process_panel_base/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit4/b1_process_panel_base/test_process_panel_base.py — gates: 17, flagged: 0
- [x] tests/test_audit4/b1_process_panel_base/test_realcov_14a_panel_base.py — gates: 4, flagged: 0
- [x] tests/test_audit4/b2_process_tab/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit4/b2_process_tab/conftest.py — gates: 0, flagged: 0
- [x] tests/test_audit4/b2_process_tab/test_process_tab.py — gates: 9, flagged: 0
- [x] tests/test_audit4/b2_process_tab/test_realcov_14a_process_tab.py — gates: 4, flagged: 0
- [x] tests/test_audit4/b3_threads_tab/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit4/b3_threads_tab/test_threads_tab.py — gates: 8, flagged: 0
- [x] tests/test_audit4/b3_threads_tab/test_realcov_14a_threads_tab.py — gates: 4, flagged: 0
- [x] tests/test_audit4/b4_memory_tab/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit4/b4_memory_tab/test_memory_tab.py — gates: 24, flagged: 0
- [x] tests/test_audit4/b4_memory_tab/test_realcov_14a_memory_tab.py — gates: 5, flagged: 0

## Flagged tests

### tests/test_audit4/a4_windows_sandbox/test_ps_sources.py

The whole module asserts on the *literal text* of generated PowerShell scripts.
For the scope-shadowing bugs (F-0008 `$using:`, F-0018 `$pid`) the production
artifact under test genuinely *is* a string, and the strongest tests assert both
"defect pattern absent" AND "correct replacement present" — those are kept as
genuine (narrow) gates. The entries below assert only a single substring's
presence with no anchoring; a refactor that keeps the substring while breaking
the actual generated script behaviour (e.g. the substring living in a comment, a
different variable, or a now-dead code branch) would not trip them. These are
N9 (log/string-presence proxy) gating something weaker than the named behaviour.

#### `test_action_reads_event_message_data` — MEDIUM — N9
- **Location:** tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:71
- **Current behavior:** asserts `"$Event.MessageData" in source` only.
- **Why it is not a gate:** the substring can be present without the log path
  actually being bound or written; it duplicates the stronger `test_no_using_scope_in_action` which already requires `$lp = $Event.MessageData`. Presence alone does not prove the action reads the message data correctly.
- **Recommended fix:** assert the full binding line (`$lp = $Event.MessageData`) and that `$lp` is subsequently used in the `Out-File` line, tying read to use.

#### `test_action_uses_local_log_path_var` — LOW — N9
- **Location:** tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:76
- **Current behavior:** asserts `"Out-File -Append -FilePath $lp" in source`.
- **Why it is weaker than named:** a real gate for "file monitor writes events"
  would require running the registered action; substring presence cannot prove
  the four event handlers actually reach this write. It is a genuine-but-narrow
  text gate, worth hardening by correlating with the four `Register-ObjectEvent` calls.
- **Recommended fix:** assert the write line appears inside the action block that the four registrations share, or count occurrences against the event count.

#### `test_uses_proc_id_variable` — LOW — N9 (redundant)
- **Location:** tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:112
- **Current behavior:** asserts `"$procId = [int]$p.ProcessId"` and `"foreach ($procId in"` are present.
- **Why it is weaker than named:** fully subsumed by `test_no_dollar_pid_assignment` (line 85) which already asserts the same replacement string plus the regex absence of `$pid =`. It adds the `foreach` substring but does not constrain that the loop body uses `$procId` for the logged PID.
- **Recommended fix:** merge into the F-0018 test and additionally assert the per-process log line emits `$procId`, not a stale capture.

#### `test_uses_owner_pid_variable` — LOW — N9 (redundant)
- **Location:** tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:152
- **Current behavior:** asserts the two `$ownerPid = [int]...OwningProcess` lines.
- **Why it is weaker than named:** identical assertions already made by `test_no_dollar_pid_assignment` (line 122); this test adds nothing beyond the same two substrings and does not verify the owner PID reaches the emitted log entry.
- **Recommended fix:** drop or extend to assert `$ownerPid` is interpolated into the network log line.

#### `test_no_hardcoded_reg_sz` — MEDIUM — N9
- **Location:** tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:162
- **Current behavior:** asserts `"|REG_SZ|" not in source`.
- **Why it is not a gate:** the F-0019 fix is "detect the real value type". Absence
  of one hardcoded literal does not prove dynamic detection; the source could
  hardcode a different literal (`|REG_DWORD|`), or omit a type entirely, and this
  test would still pass. It only forbids one specific old string.
- **Recommended fix:** generate the script, run `Get-RegValueType` against known
  REG_SZ/REG_DWORD/REG_BINARY values via real `pwsh`, and assert the emitted
  type matches each input — or at minimum assert the log line interpolates the
  `$vtype`/`$rtype` variable rather than any literal type token.

#### `test_dynamic_type_in_snapshot` — MEDIUM — N9
- **Location:** tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:172
- **Current behavior:** asserts `"Get-RegValueType" in source` and `"$vtype" in source`.
- **Why it is not a gate:** presence of a function name and a variable name does
  not prove the function is called per value or that `$vtype` is what gets
  recorded; the helper could be defined but never invoked and the test stays green.
- **Recommended fix:** assert `$vtype = Get-RegValueType ...` assignment plus that
  `$vtype` flows into the snapshot record, or execute the generated snapshot block.

#### `test_type_included_in_log_entry` — MEDIUM — N9
- **Location:** tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:178
- **Current behavior:** asserts `"$rtype" in source`.
- **Why it is not a gate:** a single variable-name substring; it does not constrain
  that `$rtype` is the registry value type, that it is computed dynamically, or
  that it lands in the `::`-delimited log line. The variable could exist in a
  dead branch.
- **Recommended fix:** assert `$rtype` appears in the actual log-line format string
  alongside the `-split '::', 3` parse, or run the generated change-handler.

### tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py

#### `test_anti_evasion_profile_recorded_in_result` — MEDIUM — N6/N10
- **Location:** tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py:1010
- **Current behavior:** sets `qmp` to a bare `MagicMock()`, calls `apply_anti_evasion(profile="workstation")`, asserts `result["profile"] == "workstation"`.
- **Why it is weak:** the expected value `"workstation"` is exactly the literal the
  test injected as the argument, and the SMBIOS application path runs against a
  `MagicMock` QMP whose `.send_command`/responses are auto-truthy, so the assertion
  only proves the function echoes its own input parameter into the result dict. A
  regression that applied nothing but still returned the requested profile label
  would pass. (The companion `test_anti_evasion_different_profiles_produce_different_smbios` at line 1035 is the real gate for profile-to-SMBIOS flow; this one is the echo.)
- **Recommended fix:** assert the profile drives an observable side effect (the
  SMBIOS entries actually applied for `workstation` differ from `default`), not
  just that the label round-trips.

#### `test_anti_evasion_techniques_reflect_profile_applied` — MEDIUM — N10
- **Location:** tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py:1053
- **Current behavior:** `qmp = MagicMock()`, asserts `result["profile"] == "laptop"` and `any("smbios" in t for t in result["techniques"])`.
- **Why it is weak:** with a MagicMock QMP every command "succeeds", so the
  techniques list is produced regardless of whether SMBIOS was genuinely applied;
  the substring `"smbios"` is generated from the profile config the test set, not
  from a verified guest mutation. It does not discriminate `laptop` from any other
  profile.
- **Recommended fix:** assert the specific SMBIOS manufacturer/product strings for
  `laptop` appear in `techniques` (the laptop-specific values), so the laptop
  profile cannot be confused with default/workstation.

#### `test_anti_evasion_different_profiles_produce_different_smbios` is a genuine gate (kept).

#### `test_yara_scan_scans_zip_artifacts_when_present` — MEDIUM — N6
- **Location:** tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py:1275
- **Current behavior:** stages a real dropped-files zip, fakes `yara.compile`, runs `yara_scan`, asserts `len(scanned_paths) > 0`.
- **Why it is weak:** the only assertion is "something was scanned". It does not
  assert *what* was scanned (the artifact extracted from the zip vs. the input
  dir), so the bug class it shares with the sibling test (F-0028: scan the zip,
  not user input) is not actually pinned here — any non-empty scan set passes,
  including one that scanned the wrong directory. The sibling
  `test_yara_scan_uses_output_dir_not_input_on_no_zip` (line 1216) does gate the
  negative; this positive test should gate that the zip artifact is the thing scanned.
- **Recommended fix:** assert a scanned path contains `artifact.bin` (the file that
  was placed in the zip) and that no scanned path is under `shared/input`.

#### `test_windows_startup_script_created` — MEDIUM — N8
- **Location:** tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py:1454
- **Current behavior:** creates the agent script, asserts `startup_scripts or agent_scripts` (i.e. at least one file matching `start_agent.*` *or* `agent.*` exists).
- **Why it is weak (F-0006 = "startup entry point wired in"):** the disjunction is
  satisfied if *only* `agent.*` exists and the start-up wrapper (the actual fix)
  is missing; the test name claims `start_agent.cmd` is produced but the assertion
  does not require it. It only checks file existence, not that the startup script
  references/launches the agent (which is the named behaviour).
- **Recommended fix:** require the `start_agent.cmd` file specifically and assert
  its contents reference the agent script (the wiring), not merely that some file exists.

#### `test_linux_startup_script_created` — MEDIUM — N8
- **Location:** tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py:1476
- **Current behavior:** asserts `sh_scripts or agent_scripts` exist for the Linux guest.
- **Why it is weak:** same disjunction problem as the Windows case — the start-up
  wrapper that F-0006 adds is not specifically required, and contents are never
  inspected, so a missing startup wire-up passes as long as an `agent.*` file exists.
- **Recommended fix:** require the `.sh` startup script specifically and assert it
  invokes the agent script.

#### `test_windows_agent_script_uses_message_data_or_global` — LOW — N7-adjacent
- **Location:** tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py:948
- **Current behavior:** asserts `has_message_data or has_global` (either `-MessageData` or `$Global:` appears).
- **Why it is weaker than named:** the accept-both-mechanisms disjunction means a
  regression that switches from one valid mechanism to a *broken* third mechanism
  is only caught by the sibling `$using:`-absence test, not here; on its own this
  asserts a substring exists somewhere in the script without tying it to the log-path
  binding. It is a genuine-but-loose text gate.
- **Recommended fix:** verify the chosen mechanism actually carries the log path
  (e.g. `-MessageData $logPath` wired to the registration, or `$Global:logPath`
  assigned and read in the action), rather than that either token appears anywhere.

## Acceptable skips (not flagged)

- tests/_helpers/realcov_process_panel.py:43 `require_windows` (used by all
  `test_realcov_14a_*` modules and `b1` realcov) — environment-capability skip:
  the real `ProcessBridge` Win32 enumeration backend exists only on Windows. This
  gates real capability on the supported platform and is a legitimate N3 exception.
- tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py:272
  `test_real_cmd_script_drives_poll_result` — `pytest.skip` only when `cmd.exe` is
  absent (impossible on Windows); legitimate environment-capability guard.
- tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py:391
  `test_real_pe_magic_rule_matches_real_binary` — `pytest.importorskip("yara")`
  skips only when the optional `yara-python` native dep is unavailable; legitimate
  optional-dependency skip (the rule-match logic is still hard-asserted when present).
- tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py:443
  `test_is_available_detects_real_qemu_and_consistent_accelerator` — branches to a
  hard `assert available is False` when no real QEMU binary exists; this is NOT a
  masking skip, it asserts the correct negative contract. Genuine gate either way.

## Notes on near-misses that are NOT flagged

- The `b2_process_tab` F-0015/F-0016/F-0017/F-0018 tests patch
  `intellicrack.ui.panels.async_bridge.run_bridge_coroutine_async` and then rely on
  the *real* production `run_bridge_coroutine_logged` (imported into
  `process_tab.py`) calling that module-global, which `_logged_success`/
  `_logged_error` wrap. The substituted dispatcher synchronously drives the genuine
  production `_on_success`/`_on_error` closures (real attach-state mutation, real
  `QMessageBox.warning`, real `_attached_pid` clearing, real `QTimer.singleShot`
  scheduling of `_on_refresh`/`_refresh_tracked`). These are genuine gates of the
  callback wiring, not N5 mock-validates-mock, and were verified against
  `src/.../process_tab.py:462-599` and `src/.../async_bridge.py:446-498`.
- The `b3_threads_tab` register tests use a `_RecordingBridge` only to capture the
  arguments production passed; the column-selection/parse logic
  (`_on_write_registers`, the hex/decimal sync at `threads_tab.py:499/535/565`) is
  real production code and the asserted integer values (0xDEADBEEF, 12345, 256,
  0xff) are independently known. Genuine gates.
- All `b4_memory_tab` unattached/attached pairs patch the *correct* production
  dispatch symbol (`memory_tab.run_bridge_coroutine_logged`) and assert exact
  dialog title/message plus dispatch-call presence/absence; the guard under test is
  real. Genuine gates.
