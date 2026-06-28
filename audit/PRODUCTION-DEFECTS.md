# Production Defects Surfaced by Strengthened Test Gates

The offender-remediation workflow ran under a strict **test-only** policy and
left now-genuine tests **correct-and-red** where they exposed real `src/` bugs.
Those bugs were then triaged and (per the user's later direction) **fixed**.

**Status legend:**
- **FIXED** — production code corrected; the gating test now passes.
- **NOT-REPRODUCED** — writer-claimed, but the gating test passes on a normal host; not a real defect here.

Last verified 2026-06-12.

---

## P-001 — PE checksum repair broadcast the wrong byte offset  ·  FIXED

- **Severity:** Medium (correctness / UI-state integrity)
- **Production symbol:** `HashingMixin._on_repair_pe_checksum`
- **Location:** `src/intellicrack/ui/panels/hex_editor/hashing.py`
- **Gating test:** `tests/test_audit4/c6_hex_hashing/test_hashing.py::TestRepairPeChecksumFiresNotify::test_repair_notifies_correct_bytes` (and `test_insert_hash_fires_notify`)
- **Was:** `notify_data_modified` fired with a hardcoded `_PE_CHECKSUM_OFFSET = 0x58`, correct only when `e_lfanew == 0`; observers redrew the wrong four bytes for any normally-laid-out PE.
- **Fix:** added `HashingMixin._pe_checksum_field_offset()` which reads `e_lfanew`
  from the document (validating the `MZ` and `PE\0\0` signatures and bounds) and
  computes `e_lfanew + 4 + 20 + 64` — the `CheckSum` field offset for both PE32
  and PE32+. The repair now notifies the real offset (`0x98` for the
  `e_lfanew=0x40` test image). Removed the misleading `_PE_CHECKSUM_OFFSET` constant.
- **Test reconciliation:** a second test (`test_insert_hash_fires_notify`) had
  codified the bug (asserted `0x58`); it and a stale `_PRODUCTION_NOTIFY_OFFSET`
  constant were corrected to assert the derived `0x98`, and the now-false
  "failing-as-designed" docstrings updated. **All 9 hashing tests pass.**

---

## PD-001 — ai_brain.svg missing root width/height attributes  ·  FIXED

- **Severity:** Low (icon rendering in high-DPI / dense layouts)
- **Production symbol / location:** `src/intellicrack/assets/icons/ai_brain.svg`
- **Gating test:** `tests/test_ui/test_icon_manager.py::TestAllMappedIconsLoad::test_all_mapped_icons_load_svg_root_width_and_height_attributes`
- **Was:** root had `viewBox='0 0 24 24'` but no `width`/`height`, so Qt could
  render it at an uncontrolled natural size (the only icon of 71 lacking them).
- **Fix:** added `width="24" height="24"` to the root element, matching the other
  70 icons. **Icon-manager tests pass.**

---

## PD-01 / PD-02 — clipboard_monitor.ps1  ·  NOT-REPRODUCED

The writer logged two clipboard-monitor defects (Add-Type failing on .NET 10;
fallback `Get-Clipboard` empty in a headless subprocess). The genuine
end-to-end gate
`tests/test_audit3/sandbox/test_clipboard_monitor.py::test_smoke_script_logs_clipboard_change`
(real `Set-Clipboard` write, real `clipboard_monitor.ps1` subprocess, 7-field
pipe-delimited record with an independent UTF-8 byte-count oracle) **passes on
this Windows 11 host**; all 10 clipboard tests pass. The claims stem from a
constrained/headless agent context (no window station) and are not defects of
the production script on a normal Windows session. **No production change made.**
The two clipboard-test docstring NOTEs still describe the test as red — stale;
a docstring-accuracy follow-up.

---

---

# Test-Infrastructure Audit Remediation (2026-06-26) — test-only policy

The 2026-06-26 audit remediation runs under a **strict test-only policy** (user
direction: *"leave gate red, document only"*). Defects surfaced by a correct new
gate are **NOT fixed in `src/`**; the gate is left correct-and-red and recorded
here for later triage.

**Status legend (this section):**
- **RED-BY-DESIGN** — gate asserts the correct contract; production code fails it; no `src/` change made.

## PD-002 — `set_thread_context` write path omits debug registers dr0–dr3  ·  RED-BY-DESIGN

- **Severity:** Medium (read/write asymmetry; hardware-breakpoint set path unusable)
- **Production symbol:** `_ProcessBridgeStateMixin._apply_native_context` / `_apply_wow64_context`
- **Location:** `src/intellicrack/bridges/process.py` (native reg_map ~L5655; wow64 reg_map_wow64 ~L5610)
- **Gating test:** `tests/test_bridges/test_process_bridge.py::TestSetThreadContext::test_set_thread_context_dr0_roundtrip`
- **Is:** `get_thread_context` **returns** `dr0`–`dr3` (native ctx L5505–5508, wow64 ctx32 L5453–5456),
  and the underlying fetch uses `CONTEXT_ALL` / `CONTEXT_I386_ALL` (both include
  `CONTEXT_DEBUG_REGISTERS`), but the `set_thread_context` write maps contain only
  general-purpose + control registers — `dr0`–`dr3` are silently dropped. Writing
  `{"dr0": <sentinel>}` therefore no-ops, so a read-back via `get_thread_context`
  returns the original `dr0`, failing the round-trip assertion. The correct
  symmetric contract (write supports every register read returns) is gated but
  unimplemented.
- **Correct fix (deferred):** add `dr0`–`dr3` -> `Dr0`–`Dr3` entries to both write
  maps (purely additive; the context flags already fetch/store them).
- **Sandbox note:** the gate is Windows-only (`SetThreadContext`/`GetThreadContext`)
  and **skips** in the Linux Docker sandbox (legitimate environment-capability skip);
  it bites only on a Windows host. No `src/` change was made.

## PD-003 — ten GhidraBridge methods never capture their remote result  ·  RED-BY-DESIGN

- **Severity:** High (ten bridge operations are non-functional against a real Ghidra)
- **Location:** `src/intellicrack/bridges/ghidra.py`
- **Mechanism:** `prepare_remote_script` (L98–145) only preserves a remote result
  when the script's **last top-level statement is an expression** (`ast.Expr`): it
  rewrites that trailing expression to a sentinel global for a follow-up
  `remote_eval`. If the script fails to parse it raises `ToolError`; if the last
  statement is anything other than an expression (e.g. a compound `if/else` block)
  it returns `sentinel=None` and **no value is ever retrieved**. Ten methods emit
  Jython that violates this contract — every one builds its result *inside* the
  branches of a trailing `if/else` (or emits invalid syntax), so the method sees
  `None` and reports a spurious failure even when the Ghidra operation succeeded.
  Verified red against the reverted production code (the audit agent's src "fix"
  was reverted per the test-only policy):
  - **`undo` / `redo`** — emit the single line `currentProgram.undo() True.`
    (resp. `redo()`), a **Python syntax error**; `prepare_remote_script` raises
    `ToolError("Failed to parse remote script")` so the round-trip never runs.
  - **`load_binary`** — the `importFile` snippet ends with `if prog is None: {...}
    else: {...}`; result uncaptured -> `import_result is None` ->
    `ToolError("...Ghidra returned no program")` on every real import.
  - **`set_data_type` / `apply_structure_at` / `create_data_type` / `create_data`**
    — trailing `if/else` with the `True`/`False` / result dict inside the branches;
    returns `success=False` / size 0 / "Structure not found" despite success.
  - **`create_function` / `delete_function` / `edit_function_signature`** — same
    trailing-`if/else` shape; return "Failed to create function" / "Function not
    found" / "No function" although `createFunction` / removal / signature edit
    actually ran.
- **Gating tests (red-by-design):**
  `tests/test_bridges/test_ghidra_wave2a_analysis.py` (load_binary),
  `tests/test_bridges/test_ghidra_wave2a_datatypes.py` (set_data_type,
  apply_structure_at, create_data_type, create_data),
  `tests/test_bridges/test_ghidra_wave2a_edits.py` (create_function,
  delete_function, edit_function_signature, undo, redo) — each drives the real
  method and asserts the correct success/return structure, which the broken
  snippets cannot produce. 12 failing assertions across these files.
- **Correct fix (deferred):** make every such snippet end with a trailing bare
  expression — assign the success flag/result dict to a local in each branch
  (`_ok = False; if ...: _ok = True`) then a bare `_ok` as the final statement;
  for undo/redo emit `currentProgram.undo()` and a trailing `True` on separate
  lines. A single audit of all `_execute_remote` call sites for compound trailing
  statements is recommended, as untested methods may share the defect. No `src/`
  change was made.

## PD-004 — FridaBridge objc_hook_method / java_hook_method crash on a reserved structlog kwarg  ·  RED-BY-DESIGN

- **Severity:** High (both hook-installation methods raise on their first line; never functional)
- **Location:** `src/intellicrack/bridges/frida_bridge.py:5600` (`objc_hook_method`)
  and `:5856` (`java_hook_method`)
- **Mechanism:** both methods open with
  `_logger.info("frida_..._hook_method_started", class_name=..., method_name=method_name)`.
  `method_name` is the name of structlog's `BoundLoggerBase._proxy_to_logger`
  first positional parameter, so passing it as a keyword collides:
  `TypeError: _proxy_to_logger() got multiple values for argument 'method_name'`.
  The exception is raised on the method's first statement, before the
  attachment guard or any script construction — so **every** call to
  `objc_hook_method` / `java_hook_method` fails, on every code path
  (happy, not-attached, error-payload). The audit recorded these methods at
  0% coverage, so the defect was latent.
- **Gating tests (red-by-design):** `tests/test_bridges/test_frida_wave2c_objc_java.py`
  — `test_objc_hook_method_*` (4) and `test_java_hook_method_*` (4) drive the
  real methods and assert the correct hook framing/result or the correct
  not-attached / error-payload `ToolError`; all 8 fail because the method raises
  `TypeError` first. (The `_deliver_after_load` helper returns early when no
  script is created so the failure surfaces the production `TypeError` rather
  than a helper index error.)
- **Correct fix (deferred):** rename the conflicting log field, e.g.
  `_logger.info("frida_objc_hook_method_started", class_name=class_name, objc_method=method_name)`
  (and likewise for the Java method). Other `_logger` calls passing
  `method_name=` anywhere in the codebase share this latent collision and should
  be audited. No `src/` change was made.

## PD-005 — get_fiber_data misclassifies every ordinary thread as a fiber  ·  RED-BY-DESIGN

- **Severity:** Medium (incorrect fiber detection for all non-fiber threads)
- **Location:** `src/intellicrack/bridges/process.py:9135` (`get_fiber_data`); the
  raw read is at `:5243` (`struct.unpack_from("<Q", raw, 0x20)`).
- **Mechanism:** `has_fiber` is computed as `isinstance(fiber_data, int) and
  fiber_data != 0`, where `fiber_data` is the TEB field at offset `0x20`. In
  `NT_TIB` that field is a **union** of `FiberData` (a pointer, set only for real
  fibers) and `Version` (a non-zero value for ordinary threads). For any thread
  that never called `ConvertThreadToFiber`, the field holds `Version` (non-zero),
  so `fiber_data != 0` is True and the method reports `has_fiber=True` for a
  thread that is **not** a fiber. Verified: `get_fiber_data` on a live CPython
  interpreter thread returns `has_fiber=True`.
- **Gating test (red-by-design):**
  `tests/test_bridges/test_process_bridge.py::TestSehFiberTls::test_get_fiber_data_returns_dict`
  asserts `has_fiber is False` for a CPython thread (which is never a fiber).
- **Correct fix (deferred):** derive `has_fiber` from the TEB `HasFiberData` flag
  (bit in `SameTebFlags`), not from `fiber_data != 0`; keep `fiber_data` as the raw
  union value. No `src/` change was made.

## PD-006 — highlighter.py rule-ordering / capture-group defects  ·  RED-BY-DESIGN

- **Severity:** Low (cosmetic syntax-highlighting only)
- **Location:** `src/intellicrack/ui/highlighter.py`
- **Mechanism:** `highlightBlock` applies the rule list in order, each rule calling
  `setFormat(match.capturedStart(), match.capturedLength(), rule.format)` so a
  later rule overwrites an earlier one over the same span, and the **whole** match
  (group 0) is formatted, not the capture group. Two consequences:
  1. **C single-line comments lose italic.** The operator rule
     `[+\-*/%&|^~<>=!]+` (`CSyntaxHighlighter._setup_rules`, ~L220) is registered
     **after** the `//[^\n]*` comment rule (~L213). The `/` characters of `//` are
     therefore recolored by the non-italic operator format, so a `//` comment is
     not italic.
  2. **Python `def`/`class` keywords recolored as function names.** The rules
     `\bdef\s+(\w+)` and `\bclass\s+(\w+)` (`PythonSyntaxHighlighter._setup_rules`)
     are registered **after** the keyword rule and format the **full** match
     (`def foo`) because `highlightBlock` uses `capturedStart()/capturedLength()`
     (group 0), not the captured name group. The `def`/`class` keyword thus gets
     the function color `#DCDCAA` instead of the keyword color `#569CD6`.
- **Gating tests (red-by-design):**
  `tests/test_ui/test_realcov_p3_ui_zero_coverage.py::TestCSyntaxHighlighter::test_single_line_comment_is_italic`
  and `::TestPythonSyntaxHighlighter::test_keyword_def_has_keyword_color`.
- **Correct fix (deferred):** register comment/string rules **after** the operator
  rule (or stop the operator class from matching `/`), and for `def`/`class` format
  only the captured name span (`capturedStart(1)/capturedLength(1)`) so the keyword
  retains its keyword color. No `src/` change was made.

## PD-007 — `yara_scan._scan_window` unpacks yara matches as 3-tuples; modern yara-python returns StringMatch objects  ·  RED-BY-DESIGN

- **Severity:** High (yara_scan is non-functional with the installed yara-python)
- **Production symbol:** `X64DbgBridge._scan_window` / `yara_scan`
- **Location:** `src/intellicrack/bridges/x64dbg.py:7977`
- **Mechanism:** `_scan_window` iterates match strings as
  `for offset_val, _identifier, match_bytes in strings_list:` (3-tuple unpack).
  Modern yara-python (≥4.x) returns `yara.StringMatch` objects in `m.strings`,
  not 3-tuples, so the unpack raises
  `TypeError: cannot unpack non-iterable yara.StringMatch object` before any
  result dict is appended. Every `yara_scan` call that finds a match therefore
  crashes instead of returning results.
- **Gating test (red-by-design):**
  `tests/test_bridges/test_x64dbg_native_helpers_wave5.py::TestYaraScan::test_live_scan_finds_known_pattern_in_ctypes_buffer`
  — allocates a ctypes buffer containing the ASCII pattern ``INTELLICRACK``,
  compiles a hex-pattern YARA rule that matches it, calls `yara_scan` over the
  buffer address, and asserts `results[0]["rule"] == "IntellicrockTestPattern"` and
  `results[0]["matched_bytes"] == b"INTELLICRACK".hex()`. The test errors with
  `TypeError` from production before any assertion is reached.
- **Correct fix (deferred):** iterate `m.strings` as `yara.StringMatch` objects and
  read `.identifier` + `.instances[].offset` / `.instances[].matched_data` instead
  of unpacking as 3-tuples. No `src/` change was made.

## PD-008 — `adjust_token_privilege` / `get_token_privileges` / `remove_privilege` no-pid path raises OverflowError  ·  RED-BY-DESIGN

- **Severity:** High (current-process privilege operations are completely unusable without an explicit pid)
- **Production symbols:** `ProcessBridge.adjust_token_privilege`, `ProcessBridge.get_token_privileges`, `ProcessBridge.remove_privilege` — the `pid=None` (no-pid) default branch
- **Location:** `src/intellicrack/bridges/process.py` ~line 4004 / 4040 (the `GetCurrentProcess` + `OpenProcessToken` call site)
- **Mechanism:** When `pid` is not supplied, the production code calls `GetCurrentProcess()` to obtain the pseudo-handle for the current process.  On 64-bit Windows `GetCurrentProcess()` returns `(HANDLE)-1`, the value `0xFFFFFFFFFFFFFFFF`.  Because `_advapi32.OpenProcessToken` has no declared `argtypes`, ctypes cannot marshal this value and raises `OverflowError: int too long to convert` before any privilege operation takes place.  The explicit-`pid` path (which calls `OpenProcess(pid)` and obtains a real handle) works correctly.
- **Gating test (red-by-design):** `tests/test_bridges/test_process_ops_wave5.py::TestAdjustTokenPrivilegeNoPidDefect::test_adjust_token_privilege_no_pid_returns_true` — calls `adjust_token_privilege("SeChangeNotifyPrivilege", enable=True)` with no `pid` and asserts the result is `True`.  In production this raises `OverflowError`, so the test is RED.
- **Correct fix (deferred):**
  1. Declare `_advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, POINTER(wintypes.HANDLE)]` and `_advapi32.OpenProcessToken.restype = wintypes.BOOL`.
  2. Declare `_kernel32.GetCurrentProcess.restype = wintypes.HANDLE` (or cast the return value before passing it) so ctypes marshals the pseudo-handle as a proper `HANDLE` rather than a raw Python `int`.
  No `src/` change was made.

## PD-009 — `timeout_seconds` never enforced in Orchestrator agent loop  ·  RED-BY-DESIGN

- **Severity:** Medium (timeout configuration field silently ignored; long-running agents cannot be aborted by timeout)
- **Production symbol:** `Orchestrator._run_agent_loop`
- **Location:** `src/intellicrack/core/orchestrator.py` ~L1215 (agent loop)
- **Mechanism:** `OrchestratorConfig.timeout_seconds` is parsed and stored but the
  agent loop body (`while iteration < max_iterations:`) is not wrapped in
  `asyncio.wait_for(...)` or any other timeout enforcement.  Any provider that blocks
  indefinitely causes the loop to hang for ever; `timeout_seconds` has no observable
  effect at runtime.
- **Gating test (red-by-design):**
  `tests/test_core/test_orchestrator_guards_wave5.py::TestTimeoutGuard::test_timeout_seconds_not_enforced_red_by_design`
  — starts the orchestrator with `timeout_seconds=0.001`; asserts
  `asyncio.TimeoutError` propagates; since no `wait_for` wraps the loop, the
  exception is never raised and pytest reports DID NOT RAISE.
- **Correct fix (deferred):** wrap `_run_agent_loop` with
  `asyncio.wait_for(self._run_agent_loop_inner(), timeout=config.timeout_seconds)`
  and re-raise as (or alongside) `OrchestratorError`. No `src/` change was made.

## PD-010 — `RustTransformNode` silently UTF-8 encodes non-hex string params  ·  RED-BY-DESIGN

- **Severity:** Medium (incorrect param coercion silently produces wrong transform output)
- **Production symbol:** `RustTransformNode.process`
- **Location:** `src/intellicrack/core/transform_pipeline.py` ~L340
- **Mechanism:** when a parameter value is a Python `str`, the node checks
  `all(c in string.hexdigits for c in val)`.  If False (non-hex), it falls through to
  `val.encode("utf-8")` and silently uses the UTF-8 bytes as the transform key/param,
  rather than raising `TransformParamError`.  A caller passing `{"key": "GG"}` expects
  a validation error; instead the string `"GG"` is encoded to `b"GG"` and used as the
  key without warning.
- **Gating test (red-by-design):**
  `tests/test_core/test_transform_pipeline_wave5.py::TestRustTransformNodeInvalidParams`
  — drives `RustTransformNode.process(data, {"key": "GG"})` and asserts
  `TransformParamError` is raised; since production silently encodes instead, `pytest.fail`
  is called with the "PD-010: RustTransformNode silently UTF-8 encoded…" message.
  Skips if `HexcoreUnavailableError` fires (hexcore not built).
- **Correct fix (deferred):** add an explicit hex-validation branch:
  `if not is_hex: raise TransformParamError(f"param {name!r} is not valid hex: {val!r}")`
  before the `val.encode("utf-8")` fallback. No `src/` change was made.

## PD-011 — `generate_timeline` has no 'resource' handler for ResourceSample events  ·  RED-BY-DESIGN

- **Severity:** Low (resource usage samples omitted from unified timeline; gaps in analysis view)
- **Production symbol:** `generate_timeline`
- **Location:** `src/intellicrack/sandbox/analysis.py` ~L550
- **Mechanism:** `generate_timeline` has 10 category handlers (file, registry, network,
  process, api, service, kernel, dll, injection, clipboard) each guarded by
  `if _should_include("X"): _timeline_add_X_events(report, events)`.
  `ExecutionReport.resource_samples` is collected during sandbox execution but there is
  no corresponding `_timeline_add_resource_events` helper; `ResourceSample` entries are
  silently skipped.  Timeline consumers see a gap wherever resource-usage spikes
  correlate with other activity.
- **Gating test (red-by-design):**
  `tests/test_sandbox/test_sandbox_analysis_wave5.py::TestGenerateTimelineResourceCategory`
  — builds an `ExecutionReport` with one `ResourceSample` and calls
  `generate_timeline(report)`; asserts `events[i]["category"] == "resource"` for at
  least one event.  Since no handler exists the assertion fails.
- **Correct fix (deferred):** add a `_timeline_add_resource_events(report, events)` helper
  that iterates `report.resource_samples` and appends `TimelineEvent(timestamp=s["timestamp"],
  category="resource", summary=f"CPU {s['cpu_percent']}% / RAM {s['memory_mb']}MB", details=…)`
  and wire it into `generate_timeline` with the matching
  `if _should_include("resource"):` guard. No `src/` change was made.

## PD-012 — `connect()` does not catch `httpx.ConnectError`; probe failure is exposed raw  ·  RED-BY-DESIGN

- **Severity:** Medium (in a no-network environment `connect()` propagates a raw
  `httpx.ConnectError` instead of the documented `ProviderError("Connection failed")`)
- **Production symbol:** `GoogleProvider.connect`
- **Location:** `src/intellicrack/providers/google.py` lines 137-144
- **Mechanism:** `connect()` catches `(ConnectionError, TimeoutError, OSError,
  ValueError, RuntimeError)` as its network-failure clause. `httpx.ConnectError`
  MRO is `ConnectError -> NetworkError -> TransportError -> RequestError -> HTTPError
  -> Exception`; it does not inherit from any of the caught types. When the
  `models.list()` probe fails because no network is available, tenacity retries once
  (default `retry_options=None` → `stop_after_attempt(1)`) and re-raises
  `httpx.ConnectError` raw. The `finally` block still executes and restores
  `GEMINI_API_KEY`, but the caller receives `httpx.ConnectError` rather than the
  contracted `ProviderError`. With a live network and an invalid key the API returns
  401 and the `except APIError` branch fires correctly.
- **Gating test:** `tests/test_providers/test_google_offline_wave5.py::test_connect_gemini_api_key_restored_after_failure`
  — the gate asserts env-var restoration (always correct) but does **not** assert the
  exception type because the exception varies by environment (PD-012 only bites in
  no-network contexts). The test is GREEN; the defect itself has no dedicated
  RED-by-design gate because the wrong exception type is only observable offline.
- **Correct fix (deferred):** add `httpx.ConnectError` and `httpx.TimeoutException`
  to the second `except` tuple in `connect()`:
  `except (ConnectionError, TimeoutError, OSError, ValueError, RuntimeError,
  httpx.ConnectError, httpx.TimeoutException) as e:`. No `src/` change was made.

---

## Result

The 2026-06-08/12 confirmed production defects are **FIXED**: 0 red-by-design tests
remain from that round. The 2026-06-26 audit-remediation section (test-only policy)
adds **PD-002** (`set_thread_context` dr0–dr3), **PD-003** (ten GhidraBridge
result-capture bugs), **PD-004** (FridaBridge objc/java hook structlog collision),
**PD-005** (`get_fiber_data` fiber/Version union misread), **PD-006**
(highlighter.py rule-ordering / capture-group), **PD-007**
(`yara_scan._scan_window` 3-tuple vs StringMatch), **PD-008**
(`adjust_token_privilege`/`get_token_privileges`/`remove_privilege` no-pid
OverflowError from un-typed `OpenProcessToken` argtypes), **PD-009**
(`timeout_seconds` never enforced in agent loop), **PD-010**
(`RustTransformNode` silently UTF-8 encodes non-hex string params), **PD-011**
(`generate_timeline` missing resource handler), and **PD-012**
(`connect()` does not catch `httpx.ConnectError`) as RED-BY-DESIGN gates, left unfixed
by design for user triage.
