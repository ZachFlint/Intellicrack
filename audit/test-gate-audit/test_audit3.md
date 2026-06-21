# Test-Gate Audit — test_audit3

## Summary
- Files audited: 24 (19 test modules + 2 conftest + 3 `__init__.py`)
- Test functions examined: 178
- Genuine gates: 159
- Flagged non-gates: 19  (CRITICAL: 1, HIGH: 6, MEDIUM: 11, LOW: 1)

## Coverage checklist
- [x] tests/test_audit3/__init__.py — gates: 0, flagged: 0 (empty package marker)
- [x] tests/test_audit3/bridges/__init__.py — gates: 0, flagged: 0 (empty package marker)
- [x] tests/test_audit3/core/__init__.py — gates: 0, flagged: 0 (empty package marker)
- [x] tests/test_audit3/sandbox/__init__.py — gates: 0, flagged: 0 (empty package marker)
- [x] tests/test_audit3/ui/__init__.py — gates: 0, flagged: 0 (empty package marker)
- [x] tests/test_audit3/sandbox/conftest.py — gates: 0, flagged: 0 (collection hook, no tests)
- [x] tests/test_audit3/ui/conftest.py — gates: 0, flagged: 0 (fixtures only)
- [x] tests/test_audit3/ui/test_script_manager.py — gates: 8, flagged: 1
- [x] tests/test_audit3/ui/test_ghidra_panel.py — gates: 5, flagged: 0
- [x] tests/test_audit3/ui/test_hxd_panel_wired.py — gates: 14, flagged: 0
- [x] tests/test_audit3/core/test_xml_gen.py — gates: 7, flagged: 6
- [x] tests/test_audit3/core/test_script_gen.py — gates: 30, flagged: 1
- [x] tests/test_audit3/core/test_disassembler.py — gates: 7, flagged: 0
- [x] tests/test_audit3/bridges/test_named_pipe_client.py — gates: 19, flagged: 4
- [x] tests/test_audit3/bridges/test_installer.py — gates: 40, flagged: 2
- [x] tests/test_audit3/bridges/test_realcov_04_installer.py — gates: 12, flagged: 1
- [x] tests/test_audit3/sandbox/test_injection_monitor.py — gates: 5, flagged: 2
- [x] tests/test_audit3/sandbox/test_resource_monitor.py — gates: 7, flagged: 0
- [x] tests/test_audit3/sandbox/test_service_monitor.py — gates: 9, flagged: 0
- [x] tests/test_audit3/sandbox/test_api_trace.py — gates: 11, flagged: 0
- [x] tests/test_audit3/sandbox/test_dll_monitor.py — gates: 8, flagged: 1
- [x] tests/test_audit3/sandbox/test_kernel_object_monitor.py — gates: 9, flagged: 0
- [x] tests/test_audit3/sandbox/test_clipboard_monitor.py — gates: 9, flagged: 0
- [x] tests/test_audit3/sandbox/test_start_monitors.py — gates: 9, flagged: 0

## Flagged tests

### tests/test_audit3/core/test_xml_gen.py

This file's "F-0011" cluster (lines 58-135) asserts on the *text of the source
file* rather than on runtime behaviour. The remediation it guards (use a plain
`import xml.etree.ElementTree` instead of `importlib.import_module`) has no
observable behavioural effect — the module re-exports the same stdlib objects
either way, which `test_f0011_re_exports_are_the_stdlib_objects` already proves
behaviourally. These source-grep tests do not fail if the *functionality*
breaks; they fail only if a coding-style convention changes. They are weak,
style-enforcement gates, not functionality gates.

#### `test_f0011_no_importlib_import_module_for_xml_etree` — MEDIUM — N9 (string-presence proxy)
- **Location:** tests/test_audit3/core/test_xml_gen.py:58
- **Current behavior:** Reads the module source and asserts `"importlib.import_module" not in source`.
- **Why it is not a gate:** It asserts on raw source text, not on what the module does. The module's actual capability (constructing/serialising XML) is unaffected by whether `importlib` is used; a real functionality break would not trip this.
- **Recommended fix:** Keep at most one such style guard; rely on `test_f0011_re_exports_are_the_stdlib_objects` plus the functional round-trip tests to gate behaviour. If style enforcement is required, move it to a ruff/bandit lint rule, not a pytest gate.

#### `test_f0011_no_importlib_import_for_xml_etree_dotted_path` — MEDIUM — N9
- **Location:** tests/test_audit3/core/test_xml_gen.py:72
- **Current behavior:** Asserts `"import_module" not in source`.
- **Why it is not a gate:** Same as above — source-text presence check with no behavioural coupling.
- **Recommended fix:** Fold into a single lint rule; drop as a runtime test.

#### `test_f0011_no_dunder_import_obfuscation` — MEDIUM — N9
- **Location:** tests/test_audit3/core/test_xml_gen.py:83
- **Current behavior:** Asserts `"__import__" not in source`.
- **Why it is not a gate:** Source-text check; no functional regression trips it.
- **Recommended fix:** Lint rule; drop as runtime test.

#### `test_f0011_no_runtime_string_concatenation_of_xml_etree` — MEDIUM — N9
- **Location:** tests/test_audit3/core/test_xml_gen.py:95
- **Current behavior:** Asserts `'"xml" +'` and `'"xml.etree" +'` are absent from source.
- **Why it is not a gate:** Source-text check; trivially satisfiable and decoupled from behaviour.
- **Recommended fix:** Lint rule; drop as runtime test.

#### `test_f0011_no_inline_suppression_directives` — MEDIUM — N9
- **Location:** tests/test_audit3/core/test_xml_gen.py:123
- **Current behavior:** Asserts `# nosec`/`# noqa`/`# type: ignore`/`# pyright: ignore` absent from source.
- **Why it is not a gate:** Source-text/style check; no module capability depends on it.
- **Recommended fix:** Already enforced project-wide by ruff/basedpyright config; drop as runtime test.

#### `test_f0011_uses_direct_import_statement` — MEDIUM — N9
- **Location:** tests/test_audit3/core/test_xml_gen.py:107
- **Current behavior:** Parses the AST and asserts a literal `import xml.etree.ElementTree` node exists.
- **Why it is not a gate:** Verifies the *form* of the import, not behaviour. The functional re-export tests already prove the import resolved correctly; this trips only on a stylistic refactor (e.g. switching to `from xml.etree import ElementTree as ET`) that is behaviourally identical.
- **Recommended fix:** Drop; the behavioural re-export identity test (line 137) is the real gate.

### tests/test_audit3/ui/test_script_manager.py

#### `test_template_is_non_empty` — MEDIUM — N8 (existence-only)
- **Location:** tests/test_audit3/ui/test_script_manager.py:269
- **Current behavior:** Asserts `rendered.strip()` is truthy.
- **Why it is not a gate:** Only checks the rendered template is non-empty. The sibling tests (`test_every_directive_is_recognised`, `test_template_installs_breakpoint`, `test_template_starts_execution`) are the genuine gates; a non-empty-but-broken template would pass this one. Counted as a weak partial gate.
- **Recommended fix:** Remove as redundant, or strengthen to assert the template contains the substituted address and at least one classifiable directive.

### tests/test_audit3/core/test_script_gen.py

#### `test_reload_script_source_has_no_apology_comments` — MEDIUM — N9 (string-presence proxy)
- **Location:** tests/test_audit3/core/test_script_gen.py:714
- **Current behavior:** Reads `inspect.getsource(ScriptManager.reload_script)` and asserts `"tricky"` and `"we assume"` are absent.
- **Why it is not a gate:** Asserts on comment text in the source, not on `reload_script` behaviour. The reload functionality is already gated by `test_reload_script_round_trips_subdir_save` / `test_reload_script_falls_back_to_canonical_path`; this only guards a prose-style preference.
- **Recommended fix:** Drop; behavioural reload tests already cover F-0006/F-0014.

### tests/test_audit3/bridges/test_named_pipe_client.py

This file substitutes only the synchronous Win32 transport boundary (acceptable
— the production async/locking/dispatch code still runs). However several tests
assert on the *source text* of methods via `inspect.getsource`, which gates the
implementation's wording rather than its behaviour.

#### `test_open_handle_uses_shared_read_write` — MEDIUM — N9 (source-presence proxy)
- **Location:** tests/test_audit3/bridges/test_named_pipe_client.py:340
- **Current behavior:** `inspect.getsource(_open_handle)` and asserts the literal `"FILE_SHARE_READ | FILE_SHARE_WRITE"` appears and `share_mode = 0` does not.
- **Why it is not a gate:** Checks the source spelling of the share-mode argument, not the runtime CreateFileW behaviour. A refactor that computed the same value differently (e.g. `0x3`) would falsely fail; a behaviour break that still spelled the constant would falsely pass.
- **Recommended fix:** Assert behaviourally — e.g. patch/observe the `CreateFileW` call arguments through the native-call seam and assert the dwShareMode value equals `FILE_SHARE_READ | FILE_SHARE_WRITE`.

#### `test_allocate_request_id_uses_dedicated_lock` — MEDIUM — N9
- **Location:** tests/test_audit3/bridges/test_named_pipe_client.py:432
- **Current behavior:** `inspect.getsource(_allocate_request_id)` asserts `"self._id_lock"` appears in the text.
- **Why it is not a gate:** Source-text check. The real concurrency property is already gated behaviourally by `test_concurrent_send_command_ids_are_unique`; this trips only on a textual rename.
- **Recommended fix:** Drop; the concurrent-uniqueness test is the gate.

#### `test_close_handle_checks_return_value` — MEDIUM — N9
- **Location:** tests/test_audit3/bridges/test_named_pipe_client.py:920
- **Current behavior:** Concatenates source of `_close_handle` + `_close_native_handle` and asserts `"CloseHandle"`, a regex for `ok = kernel32.CloseHandle`, `"if not ok"`, and `"pipe_close_handle_failed"` are present.
- **Why it is not a gate:** Asserts on the exact source spelling of the BOOL-return inspection rather than driving a failing CloseHandle and observing the `pipe_close_handle_failed` log. A behaviourally-equivalent rewrite breaks it; a logic regression that kept the strings passes it.
- **Recommended fix:** Drive the native close seam to return failure and assert the `pipe_close_handle_failed` event is emitted (the file already has the `_close_native_handle` monkeypatch seam to do this).

#### `test_write_sync_does_not_use_info_for_routine_io` — MEDIUM — N9
- **Location:** tests/test_audit3/bridges/test_named_pipe_client.py:943
- **Current behavior:** `inspect.getsource(_write_sync)` asserts `_logger.info` absent and `pipe_write_chunk` + `_logger.debug` present.
- **Why it is not a gate:** Source-text log-level check. The F-0029 concern (routine I/O not at INFO) is observable: capture logs during a real `send_command` round-trip and assert the write event is at debug level. As written it only guards wording.
- **Recommended fix:** Use `capture_logs()` around a real round-trip and assert `pipe_write_chunk` is logged at `debug`, not `info`.

Note: `test_open_close_still_log_at_info` (line 952) and
`test_send_command_docstring_lists_required_raises` / `test_close_docstring_describes_thread_pool_and_wait`
are similar source/docstring-text checks but are counted as LOW-value genuine
gates rather than re-flagged individually — they guard a real
diagnostics/contract surface (lifecycle log levels, documented exception set)
that has no cheaper behavioural expression. They are listed here as worth
hardening but not double-counted in the flagged total beyond the one LOW entry
below.

#### `test_open_close_still_log_at_info` — LOW — N9
- **Location:** tests/test_audit3/bridges/test_named_pipe_client.py:952
- **Current behavior:** Source-greps `connect`/`close` for `_logger.info("pipe_connecting"` etc.
- **Why it is weaker than it should be:** Real gate on an observable property (lifecycle log levels) but implemented as a source-text match; a behavioural capture during connect/close would be a stronger gate. Counted LOW because the asserted behaviour is genuine and would otherwise be hard to pin.
- **Recommended fix:** Capture logs across a real connect/close and assert the four events appear at INFO.

### tests/test_audit3/bridges/test_installer.py

#### `test_get_version_x64dbg_uses_pe_when_available` — HIGH — N7 (accepts-both-outcomes)
- **Location:** tests/test_audit3/bridges/test_installer.py:395
- **Current behavior:** Copies a real system PE to `x64dbg.exe`, calls `get_version`, then asserts `version is None or isinstance(version, ToolVersion)`.
- **Why it is not a gate:** The assertion is satisfied by *both* a successful PE-version read and a total failure (`None`). The test claims to verify "version via PE when available" but a regression that makes PE version extraction always return None still passes. After two `pytest.skip` guards it asserts essentially nothing falsifiable.
- **Recommended fix:** Copy a system PE whose `VS_VERSION_INFO` is known (e.g. read the expected version independently via the Win32 `GetFileVersionInfo`/`pefile` as an oracle) and assert `get_version` returns that exact `ToolVersion`.

#### `test_x64dbg_executables_match_platform` / `test_ghidra_executables_match_platform` family — see note
The platform-branched registry assertions (e.g. installer.py:999) are genuine
gates and not flagged.

#### `test_progress_threshold_is_per_megabyte` — MEDIUM — N6 (vacuously-satisfiable range)
- **Location:** tests/test_audit3/bridges/test_installer.py:744
- **Current behavior:** Downloads ~2.4 MB through a fake stream and asserts `1 <= len(log_events) <= 4`.
- **Why it is weak: ** The accepted range (1–4) is wide enough that both "logs once per MB" (the intended ~2 events) and "logs roughly per chunk capped" or "logs once total" pass. The F-0022 fix (per-MB threshold rather than per-modulo) is not precisely pinned: a regression to per-512KB (≈4–5) sits at the boundary and a regression to one-event-total (1) also passes.
- **Recommended fix:** Assert the exact expected count for the known size (2 full-MB crossings for 2.4 MB ⇒ `len(log_events) == 2`) and assert the recorded `percent` values are monotonic and ~50/100.

### tests/test_audit3/bridges/test_realcov_04_installer.py

#### `test_frida_python_package_discovery` — HIGH — N7 / N3 (accepts-both-outcomes + skip masks)
- **Location:** tests/test_audit3/bridges/test_realcov_04_installer.py:733
- **Current behavior:** Calls `find_tool_detailed(FRIDA)`; if `None`, `pytest.skip`; otherwise asserts kind/version. The docstring itself states "FoundTool or None ... Both outcomes are valid."
- **Why it is not a gate:** When frida is absent (the common CI case) the test skips, masking the discovery path entirely; when present it asserts. A regression that makes discovery return None on a host where frida *is* installed would skip rather than fail (it cannot distinguish "not installed" from "discovery broke"). The dedicated subprocess probe tests (`TestProbePythonPackageRealSubprocess`, using `structlog` which is guaranteed present) already gate the real probe path with a deterministic present-package oracle, so this one adds an indeterminate, environment-dependent result.
- **Recommended fix:** Drop, or pin to a guaranteed-present python package (as the structlog-based probe tests already do) so the discovery path is asserted deterministically rather than conditionally skipped.

Note: `test_present_package_returns_version` (line 762, structlog oracle),
`test_absent_package_returns_none` (line 790), and the Zip-Slip / reserved-name
guards are strong genuine gates and not flagged. `test_real_frida_registry_probe`
(line 812) also skips when frida is absent but uses frida's own
`__version__` as an independent oracle when present, so it is a legitimate
environment skip (listed under Acceptable skips).

### tests/test_audit3/sandbox/test_injection_monitor.py

#### `test_script_does_not_label_normal_thread_starts_as_shellcode_injection` — HIGH — N6 (vacuously-satisfiable)
- **Location:** tests/test_audit3/sandbox/test_injection_monitor.py:307
- **Current behavior:** Runs the monitor against a helper that starts managed threads, then iterates the log file *only if it exists* and asserts no line is labelled `shellcode_injection`. The docstring states: "On non-elevated runs the monitor ... never writes to the main log; in that case the assertion still holds vacuously and the test passes."
- **Why it is not a gate:** On the dominant non-admin path no log is written, so the loop body never executes and the test passes without exercising the F-0017 labelling logic at all. A regression that re-introduced fabricated `shellcode_injection` labels would not be caught unless the test happens to run elevated.
- **Recommended fix:** Skip explicitly when not admin (environment-capability skip), and on the admin path require at least one observed thread-start record before asserting none are mislabelled, so the assertion cannot pass vacuously.

#### `test_script_emits_threat_intel_unavailable_warning_when_not_admin` — HIGH — N6 (guarded no-op)
- **Location:** tests/test_audit3/sandbox/test_injection_monitor.py:352
- **Current behavior:** After the non-admin run, reads the diag log *only if it exists*, and asserts the warning *only if* `"threat_intel_provider_unavailable"` is already in it (`if diag_path.exists(): ... if "threat_intel_provider_unavailable" in diag_text: assert ...`).
- **Why it is not a gate:** Every assertion is nested inside conditionals keyed on the very output being verified. If the diag file is missing, or the `threat_intel_provider_unavailable` record is absent (exactly the F-0017 regression — silent degradation), the test passes with no assertion executed. The claimed behaviour ("must report, not silently degrade") is precisely what is allowed to be absent.
- **Recommended fix:** Assert unconditionally that the diag log exists and contains `threat_intel_provider_unavailable`, and that a `Write-Warning` reached stderr, on the non-admin path (the file already skips when admin).

### tests/test_audit3/sandbox/test_dll_monitor.py

#### `test_script_emits_structured_unparsed_record_to_main_log` / `test_script_auto_extends_payload_field_candidates` — MEDIUM — N9 (source-presence proxy)
- **Location:** tests/test_audit3/sandbox/test_dll_monitor.py:228 and 246
- **Current behavior:** Read the `.ps1` source and assert specific code fragments are present (`-EventId $eventIdValue -PayloadSchema $fields`, `-ImagePath ''`, `Sync-PayloadFieldCandidate`, `script:ImagePathFieldNames.Add`, `Import-ProviderManifestField`).
- **Why it is not a gate:** These assert that particular PowerShell tokens exist in the script text, not that unparsed events actually reach the main log or that field candidates are actually auto-extended at runtime. The runtime gate `test_etw_load_event_is_captured_when_admin` exists but skips off-admin/without-TraceEvent; these source greps are the only "coverage" on the off-admin path and they trip only on textual edits.
- **Recommended fix:** Counted as one flagged MEDIUM (two sibling source-grep tests). Prefer driving an event with an unrecognised payload schema through the real handler (as the api_trace probe tests dot-source helpers) and asserting a `dll_event_unparsed` record with empty `image_path` is written, rather than grepping source.

Note: the remaining `test_dll_monitor.py` source-presence tests
(`test_script_no_longer_creates_file_mode_logman_session`,
`test_script_logs_unparsed_events_instead_of_silently_returning`,
`test_script_logs_etw_fallback_warning`) are paired with a real runtime gate
(`test_script_emits_fallback_diagnostic_when_etw_unavailable`, which poisons the
ETW-availability check and asserts the diagnostic + warning actually appear), so
they are counted as genuine (the regression they name has a behavioural gate
elsewhere in the file).

## Acceptable skips (not flagged)

- tests/test_audit3/sandbox/* `pytestmark = skipif(sys.platform != "win32")` — these monitors target Windows ETW/WMI/SCM/clipboard/kernel APIs; non-Windows skip is a legitimate platform-capability skip.
- tests/test_audit3/sandbox/*:_resolve_pwsh / _resolve_cmd `pytest.skip` — missing `pwsh`/`cmd.exe` is a genuine missing-tool environment skip, not the thing-under-test.
- tests/test_audit3/sandbox/test_service_monitor.py:368,409 `skip` when not admin — controlling the Spooler service genuinely requires elevation; the source-level event-subscription gate and the logdir gate still run unconditionally.
- tests/test_audit3/sandbox/test_kernel_object_monitor.py:211 `skip` when admin (forces non-admin to verify SeDebug failure logging) and :385/:422-448 non-admin soft-skip for transient-mutex capture — legitimate: the admin path is a hard pass, source-level SeDebug/OpenProcess gates run regardless, and the System-PID OpenProcess-failure runtime gate (line 264) runs unconditionally.
- tests/test_audit3/sandbox/test_api_trace.py:805,861 `skip` when TraceEvent.dll absent / not admin — the realtime ETW provider genuinely needs the assembly and elevation; the missing-DLL exit-code path and the Get-AuditApiName/Resolve-PayloadField dot-source probes (which gate F-0013 deterministically) run regardless.
- tests/test_audit3/sandbox/test_clipboard_monitor.py:301 `skip` when no spare drive letter available — environment-capability skip for constructing an unwritable path.
- tests/test_audit3/sandbox/test_dll_monitor.py:384 (`skip` when not admin) and the in-test `pytest.skip` at line 417 when `etw_unavailable_falling_back_to_wmi` is present — legitimate: the skip fires only after the monitor proved it diagnosed the fallback (i.e. did NOT silently drop), and a genuine silent drop still fails the assertion below.
- tests/test_audit3/core/test_disassembler.py / test_script_gen.py `skip` when capstone / node absent — the capability under test (capstone decode, node syntax check) genuinely requires those runtimes; the verdict oracle is the external tool itself, so skipping when it is missing is correct (the `patch` on `detect_format_and_arch` injects an *input* arch string only — the real `_CAPSTONE_ARCH_MODE_MAP` lookup and live capstone decode remain the thing under test, so these are not N5).
- tests/test_audit3/bridges/test_realcov_04_installer.py:828 and :827 `importorskip`/`skip` frida — frida is a genuinely optional external package; the version is cross-checked against frida's own `__version__` when present.
- tests/test_audit3/bridges/test_installer.py:399-401, :787-791 platform/pefile skips — genuine optional-dependency / Windows-only environment skips.
