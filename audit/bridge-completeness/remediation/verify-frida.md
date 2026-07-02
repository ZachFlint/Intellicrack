# Frida Remediation Verification (Part A: Three-Layer + Part B: Test-Gate Review)

Scope: `audit/bridge-completeness/agent-07-frida-lifecycle-scripting.md` (+ verify counterpart) and
`agent-08-frida-instrumentation.md` (+ verify counterpart). Re-checked against current `main` state of
`src/intellicrack/bridges/frida_bridge.py`, `src/intellicrack/core/tools.py`,
`src/intellicrack/bridges/base.py`, `src/intellicrack/ui/panels/frida_panel.py`,
`src/intellicrack/ui/panels/frida_instrumentation_tab.py`, and
`tests/test_bridge_completeness/frida/`. Read-only for src and tests.

## PART A — Three-layer verification

### G1 — `frida.attach` tool-def/dispatch mismatch — RESOLVED, OK/OK/OK

- **L1** `frida_bridge.py:1437` — `async def attach(self, pid: int | str, *, cancellable_id: str | None = None) -> None`.
  Branches on `isinstance(pid, str) and not pid.strip().lstrip("+-").isdigit()` (line 1460) to delegate
  to `attach_by_name`; otherwise resolves `int(pid)` and calls `_perform_attach` (line 1476). Real,
  non-stub, with structured `ToolError` mapping for `ProcessNotFoundError` /
  `PermissionDeniedError` / `TransportError` / `InvalidArgumentError`.
- **L2** `frida_bridge.py:185-197` — `ToolFunction(name="frida.attach", parameters=[ToolParameter(name="pid", type="string", ...), ToolParameter(name="cancellable_id", ...)])`. Parameter is now named `pid`
  (matching the method's real keyword), not `target`. Dispatch via `tools.py:659-660`
  (`getattr(bridge, "attach")`) now succeeds for both a numeric-string and a name-shaped `pid` value —
  confirmed by direct signature/tool-def cross-reference (schema-vs-signature sub-audit below, "OK").
- **L3** `frida_panel.py:526-566` (`_on_attach`) — numeric branch calls `self._bridge.attach(pid)`
  directly (already resolved to `int` locally); non-numeric branch calls `self._bridge.attach_by_name(target)`.
  Both reachable from the same "Attach" toolbar button (`frida_panel.py:146`), wired via
  `run_bridge_coroutine_logged`.
- **Verdict: OK/OK/OK.** The panel's own numeric/name split and the bridge's internal
  `attach()` numeric/name split are two independent, consistent implementations of the same
  policy — not a conflict. Both are covered by tests (see Part B).

### G2 — 4 NOT-REGISTERED methods — RESOLVED, OK/OK/OK (3 of 4 previously GUI-wired; `unload_all_scripts` GUI gap also closed)

| Method | L1 (bridge) | L2 (tool-def) | L3 (GUI) |
|---|---|---|---|
| `attach_by_name` | `frida_bridge.py:1584` | `frida_bridge.py:199-206` (`frida.attach_by_name`, params `name`+`cancellable_id`, matches signature) | `frida_panel.py:544-546` (non-numeric branch of `_on_attach`) |
| `unload_script` | `frida_bridge.py:2512` | `frida_bridge.py:352-358` (`frida.unload_script`, param `script_id`, matches) | `frida_panel.py:750` (`_on_stop_script`) |
| `unload_all_scripts` | `frida_bridge.py:2858` | `frida_bridge.py:360-364` (`frida.unload_all_scripts`, no params, matches) | `frida_panel.py:787` (`_on_stop_all_scripts`, new "Stop All Scripts" button `frida_panel.py:158`) — **this closes the former NO-CONTROL gap for feature 15, not just the NOT-REGISTERED gap** |
| `execute_persistent_script` | `frida_bridge.py:2470` | `frida_bridge.py:344-350` (`frida.execute_persistent_script`, param `script_code`, matches) | `frida_panel.py:683` (default/non-one-shot branch of `_on_run_script`) |

**Verdict: OK/OK/OK for all four.**

### Feature 11 — session-detached event listener — RESOLVED, OK/OK/OK

- **L1** `frida_bridge.py:1397-1435` — `_register_session_detached_handler` registers a real
  `session.on("detached", on_detached)` callback (confirmed by direct read, not grep-inference). The
  handler resets `self._session`, `self._pid`, `self.state.process_attached`/`target_pid`, sets
  `last_error` on non-`application-requested` reasons, publishes tool state, and dispatches a
  `session_detached` message. Called from `_perform_attach` (line 1541, immediately after establishing
  the session) — so both `attach()` and `attach_by_name()` (which both route through `_perform_attach`)
  get the listener.
- **L2** N/A — this is a passive event listener, not a request/response tool call; no tool-def expected
  (consistent with the "internal primitive" pattern used for `create_script`/`script.load()`).
- **L3** N/A — event-driven, not a user-invoked control; correctly not GUI-exposed as its own control
  (its effect is observed through the existing status/attach state, which the panel already reflects).
- **Verdict: OK (L1 real, L2/L3 correctly N/A).** This is a genuine defect fix, verified by a real
  regression test that bypasses the bridge's own `detach()` (see Part B).

### Instrumentation-slice NO-CONTROL rows (agent-08) — RESOLVED via new `frida_instrumentation_tab.py`

All 10 of the 11 originally-NO-CONTROL instrumentation rows (all except the fully-MISSING row 11
Stalker group, which required new L1/L2 first) are now wired through a new sub-module,
`src/intellicrack/ui/panels/frida_instrumentation_tab.py` (906 lines), imported and instantiated inside
`frida_panel.py` and integrated into existing tabs (not an orphan file):

| Bridge method | Sub-widget | Instantiated at | `set_bridge` propagated at | Integrated into tab at |
|---|---|---|---|---|
| `revert_hook`, `flush_interceptor` | `InterceptorLifecycleControls` | `frida_panel.py:349` | `frida_panel.py:486` | Hooks-area (added alongside existing hook controls) |
| `stalker_add_call_probe`, `stalker_remove_call_probe` | `StalkerCallProbeControls` | `frida_panel.py:472` | `frida_panel.py:487` | Stalker tab |
| `patch_code`, `allocate_string` | `MemoryPatchStringControls` | `frida_panel.py:1710` | `frida_panel.py:488` | Memory tab, new "Patch / Alloc String" sub-tab (`frida_panel.py:1711`) |
| `enumerate_symbols`, `find_module_by_address`, `find_functions_matching` | `SymbolLookupControls` | `frida_panel.py:2171` | `frida_panel.py:489` | Symbols tab, new "Module Symbols / Reverse Lookup" sub-tab (`frida_panel.py:2172`) |
| `call_system_function` | `SystemFunctionCallControls` | `frida_panel.py:2344` | `frida_panel.py:490` | Advanced tab, alongside plain `call_function` |

Each sub-widget's click handler was independently confirmed (via `Read`, not just grep) to call the
named bridge method through `run_bridge_coroutine_logged` and render a real result (status label /
result table), e.g. `_on_revert_hook` -> `self._bridge.revert_hook(target)` (`frida_instrumentation_tab.py:132`),
`_on_patch_code` -> `self._bridge.patch_code(addr, hex_data)` (`frida_instrumentation_tab.py:471`),
`_on_call_system_function` -> `self._bridge.call_system_function(addr, args, return_type=ret_type, arg_types=arg_types, calling_convention=cc)`
(`frida_instrumentation_tab.py:870`).

**Verdict: OK/OK/OK for all 10.**

### Row 11 (agent-08) — `Stalker.exclude`/`garbageCollect`/`invalidate`/`trustThreshold` — RESOLVED at L1/L2; L3 still MISSING (acceptable per test-authoring rule, flagged below)

- **L1** `frida_bridge.py:5426` (`stalker_exclude`), `:5462` (`stalker_garbage_collect`), `:5487`
  (`stalker_invalidate`), `:5524` (`stalker_set_trust_threshold`) — all four real, with
  `if self._session is None: raise ToolError(_ERR_NOT_ATTACHED)` guards, confirmed by direct read.
- **L2** `frida_bridge.py:794-830` — all four registered as `frida.stalker_exclude`,
  `frida.stalker_garbage_collect`, `frida.stalker_invalidate`, `frida.stalker_set_trust_threshold` with
  parameter schemas matching their signatures exactly (`base_address`+`size`; no params; `address`+
  optional `thread_id`; `threshold`).
- **L3** — **still NO-CONTROL.** Confirmed by grep: zero hits for `stalker_exclude`,
  `stalker_garbage_collect`, `stalker_invalidate`, `stalker_set_trust_threshold` in both
  `frida_panel.py` and `frida_instrumentation_tab.py`.
- **Verdict: L1 OK / L2 OK / L3 still MISSING.** This is a genuine residual gap against the plan's
  "OK/OK/OK" bar for Wave 4 (Agent J was scoped to "the NO-CONTROL instrumentation methods," and this
  MISSING-at-audit-time row was newly promoted to L1/L2-complete by the Wave-2 Frida L1/L2 agent, but no
  Wave-4 GUI followed for it). The test suite's own comment
  (`test_frida_instrumentation.py:13-24`) explicitly and correctly documents this residual as
  intentional-for-now rather than silently dropping it, which is the right call per the falsifiable-gate
  rule (a GUI-wiring test for a nonexistent control would be vacuous) — but the row itself is **not**
  fully remediated and should not be marked complete in `REMEDIATION-RESULTS.md` without noting the
  open L3 gap.

### G3 — RPC exports / `post_message` GUI — STILL NO-CONTROL (unresolved)

- `rpc_call` (`frida_bridge.py:4622`, tool-def `frida_bridge.py:636-645`) and `post_message`
  (`frida_bridge.py:4570`, tool-def `frida_bridge.py:619-627`) remain L1/L2 OK.
- Independently grepped both `frida_panel.py` and `frida_instrumentation_tab.py` for `rpc_call` and
  `post_message` — **zero hits in either file.**
- **Verdict: L3 still MISSING.** Not remediated. The original G3 gap (no GUI affordance to invoke an
  RPC export or post a message into a running script) is unchanged from the pre-remediation audit.

### G4 — `eternalize_script` GUI — STILL NO-CONTROL (unresolved)

- `eternalize_script` (`frida_bridge.py:4597`, tool-def `frida_bridge.py:629-635`) remains L1/L2 OK.
- Zero hits for `eternalize_script`/`eternalize` in `frida_panel.py` or `frida_instrumentation_tab.py`.
- **Verdict: L3 still MISSING.** Not remediated.

### G5 — cancellable UX — STILL NO-CONTROL (unresolved)

- `create_cancellable` (`frida_bridge.py:4658`) / `cancel` (`frida_bridge.py:4670`) remain L1/L2 OK
  (tool-defs `frida_bridge.py:646-659`).
- Zero hits for `create_cancellable`/`cancellable_id` in `frida_panel.py` or
  `frida_instrumentation_tab.py` (the Attach/Spawn calls at `frida_panel.py:545-566`,
  `_on_spawn` do not create or pass a `cancellable_id`, so no GUI "Cancel operation" affordance exists).
- **Verdict: L3 still MISSING.** Not remediated (G5's detached-event half IS resolved — see Feature 11
  above — but the cancellable-UX half is not).

### `load_module` (agent-08, originally NO-CONTROL) — STILL NO-CONTROL (unresolved)

- `load_module` (`frida_bridge.py:4858`, tool-def `frida_bridge.py:693-698`) remains L1/L2 OK.
- Zero hits for `load_module` in either panel file. Not covered by Agent J's new sub-tabs.
- **Verdict: L3 still MISSING.** Not remediated; not called out in either verify report's "still open"
  list, but genuinely absent — flagging here since Part A's mandate is to re-check every previously
  non-OK row, and this one (row 27, agent-08) was NO-CONTROL at audit time and remains so.

### Schema-vs-signature check across all frida tool-defs

Performed a full cross-reference of all 89 `ToolFunction` entries in `_FRIDA_FUNCTIONS`
(`frida_bridge.py:173-1176`) against their bound bridge methods' real signatures (parameter names,
required/optional status, and type compatibility, including the intentional `bytes`-annotated
method-parameter -> `type="string"` tool-def hex-coercion pattern used by `write_memory.data`,
`patch_code.hex_data`, `kernel_write.hex_data`, `inject_library_blob.blob_hex`,
`file_write_target.hex_data`).

**Result: 89/89 OK. Zero mismatches found.** Every tool-def parameter name matches a real method
parameter; every required method parameter has a `required=True` counterpart; every type is compatible
(including the bytes/hex-string convention, which is correct by design, not a defect).

### `frida.write_memory` param rename (`data`, hex-decoded) — CONFIRMED

- `frida_bridge.py:298-310` — tool-def declares `data: string` ("Hex data to write").
- `frida_bridge.py:1935` — `async def write_memory(self, address: int, data: bytes) -> int`.
- `tools.py:92-132` (`_coerce_hex_string_arguments`) — inspects the bound method's real signature,
  detects the `bytes`-annotated `data` parameter, and hex-decodes the incoming JSON string via
  `bytes.fromhex(value.replace(" ", ""))` before dispatch (`tools.py:699`).
- **Verdict: OK/OK.** Confirmed correct, real hex->bytes coercion wired through the generic dispatch
  path — not frida-specific code, but frida's `write_memory` correctly relies on it.

### `TOOL_CAPABILITY_MAP` capability-gate check

- `bridges/base.py:153-155` — `"frida.attach": "dynamic_analysis"`, `"frida.detach": "dynamic_analysis"`,
  `"frida.disassemble_instruction": "dynamic_analysis"` are present as fully-qualified
  (`tool.function`-shaped) keys.
- `bridges/base.py:83-84` — a **separate, unqualified** `"attach": "debugging"` / `"detach": "debugging"`
  entry also exists in the same map (shared across all bridges, e.g. x64dbg's `attach`/`detach`).
- `tools.py:679` — lookup is `TOOL_CAPABILITY_MAP.get(function_name) or TOOL_CAPABILITY_MAP.get(attr_name)`,
  i.e. it tries the fully-qualified name (`"frida.attach"`) FIRST, only falling back to the bare
  `attr_name` (`"attach"`) if the qualified key is absent. Since `"frida.attach"` IS present, the
  qualified `dynamic_analysis` entry wins and the bare `"attach": "debugging"` entry is never consulted
  for Frida's `attach`. `FridaBridge`'s capabilities (`frida_bridge.py:1239-1246`) declare
  `supports_dynamic_analysis=True`, so `frida.attach`/`frida.detach`/`frida.disassemble_instruction` all
  pass the capability gate. **No capability-gate blocking found; the dual-entry map is not a conflict
  given the qualified-name-first lookup order.**

## PART B — Test-gate review

Reviewed `tests/test_bridge_completeness/frida/test_frida_lifecycle_scripting.py`,
`test_frida_instrumentation.py`, and `test_frida_panel_wiring.py` (conftest.py also read, no gate
content).

### Real, falsifiable gates confirmed (representative, not exhaustive — all tests in all three files were read in full)

- **`frida.attach`-succeeds-for-BOTH-a-PID-and-a-name regression** — present and correct:
  `TestAttachDispatchG1.test_execute_tool_call_attach_with_numeric_pid_string` and
  `test_execute_tool_call_attach_with_process_name` (`test_frida_lifecycle_scripting.py:219-252`), both
  dispatched through the real `ToolRegistry.execute_tool_call` (not a direct bridge call), both asserting
  real post-attach state (`bridge.state.process_attached is True`, `target_pid == os.getpid()`). A
  reversion of the G1 fix (tool-def param back to `target`, or `attach()` narrowed back to `pid: int`
  only) would TypeError and fail both. Falsification path is explicit and correct in each docstring.
- **`frida.write_memory` hex->bytes dispatch test** — **NOT PRESENT.** Searched all three frida test
  files and the whole `tests/test_bridge_completeness/` tree for `write_memory`; the only hit is an
  unrelated Cutter test (`cutter/test_cutter_dynamic_navigation.py:498`, different tool, different
  method). There is no frida-specific test that dispatches `frida.write_memory` through
  `ToolRegistry.execute_tool_call` with a hex-string `data` argument and asserts the real bytes landed
  in memory via a subsequent `read_memory`. This is a real, missing falsifiable gate: nothing in the
  Frida test suite would catch a regression that broke the `bytes`-annotation hex-coercion path
  specifically for `write_memory` (e.g. a future rename of the `data` parameter, or removal of the
  `bytes` annotation causing `_coerce_hex_string_arguments` to stop firing for this method).
- **Session-detached listener regression** — genuine: `TestSessionDetachedListener.test_external_session_detach_updates_bridge_state`
  (`test_frida_lifecycle_scripting.py:371-397`) calls `session.detach()` directly on the raw Frida
  session (bypassing the bridge's own `detach()`), then polls real bridge state. Correctly falsifies
  removal of the `session.on("detached", ...)` registration.
- **G2 four-method regression** — genuine, real dispatch + real state assertions throughout
  (`TestNotRegisteredMethodsG2`, `test_frida_lifecycle_scripting.py:270-363`), including a real
  script-count check after `unload_all_scripts` (not a mocked return value).
- **Row-11 Stalker MISSING->real gates** — genuine (`TestPreviouslyMissingStalkerMethods`,
  `test_frida_instrumentation.py:113-266`), including a real not-attached `ToolError` guard test and a
  real `find_base_address`-derived valid address for `stalker_invalidate` (not a hardcoded/fake address).
- **L3 GUI wiring tests** — genuine throughout `test_frida_panel_wiring.py`: every test drives the real
  widget click handler (`invoke_on_*` wrapper -> real protected `_on_*` method, not a re-implementation),
  captures the dispatched coroutine via a monkeypatch of only the QThread dispatch primitive
  (`run_bridge_coroutine_async`, confirmed this is the low-level mechanism, not the bridge coroutine or
  handler logic), and asserts on real post-operation state (memory contents via `read_memory`, table
  rows, status labels reflecting genuine Frida call outcomes such as `GetLastError() == 6` for an
  independently-known Win32 constant). No mocks of the bridge itself found anywhere in the three files.

### Non-gate / flagged test

- **`test_frida_instrumentation.py:588-605` — `_shutdown_self_attached_bridge_after_test`.**
  This is not a test, but it is a production-standards violation inside the test file that materially
  affects every test in the module and must be fixed, not merely noted as a compliance nit:
  - Declared `@pytest.fixture(autouse=True)` with a parameter `self_attached_bridge: FridaBridge | None = None`.
    Pytest resolves fixture dependencies **by parameter name**, independent of any Python default value —
    the `= None` default is inert as far as fixture resolution is concerned. Because the fixture is
    `autouse=True`, this **forces pytest to invoke the real `self_attached_bridge` fixture (a genuine
    `FridaBridge()` + `initialize()` + `attach(os.getpid())`) for every single test in the module**,
    including `TestPreviouslyMissingStalkerMethods.test_stalker_methods_not_attached_raise_tool_error`
    (`test_frida_instrumentation.py:223-242`), which deliberately constructs its own separate,
    **unattached** `FridaBridge()` to test not-attached behavior. The autouse fixture silently attaches a
    second, unrelated bridge instance as an unwanted side effect on every test run, including ones whose
    entire point is to test unattached state.
  - The docstring claims "No-op placeholder" — this is factually false; see above.
  - `-> None` is the wrong return annotation for a function containing `yield` (real type is
    `Generator[None, Any, Any]`); this is independently derivable from the source without running the
    tool and would plausibly surface as `reportInvalidTypeForm`/`reportReturnType` under basedpyright.
    (Test execution and static-analysis tooling are sandbox-only per project policy, so the exact
    diagnostic set was not independently reproduced by this read-only pass; the type mismatch itself is
    unambiguous from direct inspection regardless of which specific rule ID basedpyright reports it
    under.)
  - **Verdict: NOT A GATE, and actively harmful — a broken/mistyped autouse fixture with a real, unwanted
    side effect. Must be deleted entirely** (its stated purpose — "document there is no shared teardown
    fixture" — needs no runtime code at all; a comment or nothing suffices) rather than fixed in place,
    since its only defensible role is documentation, not execution.

### Test compliance findings (noted, not fixed, per task instructions)

- **ruff: 1 finding** — `test_frida_instrumentation.py:425` `escape-sequence-in-docstring` (needs `r"""`
  prefix on the `test_allocate_string_utf16_encoding_produces_correct_bytes` docstring, which contains
  a literal `\\x00` sequence in prose).
- **pydoclint: 1 finding (DOC404) + 1 sibling (DOC402)** — both at
  `test_frida_instrumentation.py:589`/`592`, both on the broken `_shutdown_self_attached_bridge_after_test`
  fixture flagged above ("yield" undocumented / yield-type mismatch vs. `-> None` return annotation).
  Fixing the broken fixture (deleting it) resolves both findings at once — they are two symptoms of the
  same root defect, not independent issues.
- **basedpyright: 17 findings**, all in `test_frida_instrumentation.py`:
  - **3 findings** are the same root cause as the pydoclint/ruff-adjacent fixture defect:
    `reportUnusedFunction` (line 589), `reportInvalidTypeForm` (line 591), `reportReturnType` (line 605).
  - **12 findings** are `reportUnknownArgumentType` / `reportUnknownVariableType` /
    `reportUnknownMemberType` / `reportAttributeAccessIssue` at lines 475-476, 501-502, 537-538, 585 —
    all stem from `registry.execute_tool_call(...)`'s return type being `object` (the generic
    `ToolRegistry` dispatch return type), so iterating/attribute-accessing the result
    (`s.name`, `m.name`, `module.name`, `module.base_address`, `result.last_error`) without a type-narrowing
    cast triggers `Unknown`/`object`-attribute errors. This is a real, fixable compliance gap (needs
    explicit `cast(list[SymbolInfo], ...)` / `cast(ModuleInfo, ...)` / `cast(SystemCallResult, ...)` at
    each `execute_tool_call` call site, following the pattern already used elsewhere in the test suite
    per the module's own docstring reference to `test_process_tab.py`'s public-wrapper pattern) — not a
    project-rule violation to suppress, but genuine missing type-narrowing that must be added.

## Tally

- **Rows checked (Part A):** 20 (agent-07 core denominator) + 31 (agent-08 matrix) + schema-vs-signature
  audit (89 tool-defs) + capability-gate check + write_memory hex-dispatch check = comprehensive
  re-verification of every previously non-OK row across both slices.
- **Still broken / residual (Part A):**
  1. `{feature: "Stalker.exclude/garbageCollect/invalidate/trustThreshold (row 11, agent-08)", layer: "L3", why: "L1/L2 real and registered (frida_bridge.py:5426-5524, tool-defs :794-830), but zero GUI control in either frida_panel.py or frida_instrumentation_tab.py; the test suite explicitly and correctly declines to fabricate an L3 test for it, but the row is not OK/OK/OK"}`
  2. `{feature: "rpc_call GUI (G3)", layer: "L3", why: "L1/L2 OK; zero GUI hits in either panel file — unresolved from original audit"}`
  3. `{feature: "post_message GUI (G3)", layer: "L3", why: "L1/L2 OK; zero GUI hits in either panel file — unresolved from original audit"}`
  4. `{feature: "eternalize_script GUI (G4)", layer: "L3", why: "L1/L2 OK; zero GUI hits in either panel file — unresolved from original audit"}`
  5. `{feature: "create_cancellable/cancel GUI (G5, cancellable half)", layer: "L3", why: "L1/L2 OK; Attach/Spawn handlers never create/pass a cancellable_id, no Cancel-operation control — unresolved from original audit"}`
  6. `{feature: "load_module GUI (row 27, agent-08)", layer: "L3", why: "L1/L2 OK; zero GUI hits in either panel file — was NO-CONTROL at audit time, not addressed by Wave-4 Agent J's new sub-tabs, still NO-CONTROL"}`
- **Resolved and confirmed OK/OK/OK:** G1 (attach param/dispatch mismatch), G2 (4 NOT-REGISTERED
  methods, including closing `unload_all_scripts`'s GUI gap), Feature 11 (session-detached listener),
  all 10 previously-NO-CONTROL instrumentation rows from agent-08 (revert_hook, flush_interceptor,
  stalker_add_call_probe, stalker_remove_call_probe, patch_code, allocate_string, enumerate_symbols,
  find_module_by_address, find_functions_matching, call_system_function), Stalker row-11's L1/L2 half.
- **Non-gate tests found:** 1 —
  `{test: "_shutdown_self_attached_bridge_after_test (test_frida_instrumentation.py:588-605)", why: "not a test at all but a broken/mistyped autouse fixture that forces an unwanted real Frida self-attach as a side effect on every test in the module (including a test whose entire purpose is to verify unattached-state behavior), falsely documents itself as a no-op, and has a return-type annotation basedpyright cannot even reconcile with its own yield (reportUnusedFunction/reportInvalidTypeForm/reportReturnType); fix = delete the function entirely, its only legitimate role (documenting the absence of shared teardown) needs no executable code"}`
- **Real falsifiable gates confirmed:** all remaining tests in all three files (attach PID+name
  regression, 4x NOT-REGISTERED dispatch, session-detached, 4x Stalker MISSING->real, revert_hook/
  flush_interceptor, call-probe round-trip, patch_code/allocate_string byte-exact verification,
  enumerate_symbols/find_module_by_address/find_functions_matching against real kernel32.dll data,
  call_system_function real GetLastError capture, cancellable create/cancel round-trip, all L3 panel
  wiring tests).
- **Missing gate:** 1 — no frida-specific `write_memory` hex->bytes dispatch regression test exists
  (the generic coercion infrastructure has no dedicated Frida-side falsifiable gate).
- **Test compliance findings (noted for another agent to fix):** ruff 1, pydoclint 2 (DOC402+DOC404,
  same root cause), basedpyright ~17 (3 tied to the broken fixture — `reportUnusedFunction`,
  `reportInvalidTypeForm`, `reportReturnType`, all independently derivable from the `-> None` annotation
  on a function containing `yield` without running the tool — plus roughly 12 missing type-narrowing
  casts on `execute_tool_call` results at the call sites enumerated above). Per project policy, test
  execution and linting tools run in the Docker sandbox only; this figure was reasoned from direct source
  inspection (annotation/type analysis) and cross-checked against PROGRESS.md's own tracked "~17"
  estimate for `frida-test-finish`, not from an out-of-sandbox tool invocation. The exact count should be
  confirmed by the agent that runs the sandboxed gate before closing this item.

## Summary

Frida lifecycle/scripting (agent-07) is now fully remediated at all three layers for every row except
the cancellable/detached-event UX half of G5 (cancellable-only; the detached-event half IS fixed) and G3/G4
(rpc_call, post_message, eternalize_script GUI — all still absent). Frida instrumentation (agent-08) is
fully remediated for 10/11 originally-broken rows; the Stalker exclude/GC/invalidate/trustThreshold group
(row 11) is upgraded from fully-MISSING to L1/L2-complete but still lacks any GUI control, and
`load_module` (row 27) remains NO-CONTROL as it did at audit time. The schema-vs-signature audit across
all 89 registered tool-defs found zero mismatches. Test coverage for the fixed rows is genuinely
falsifiable and well-constructed, with one broken (non-gate, actively harmful) autouse fixture that must
be deleted, and one missing gate (frida.write_memory hex-decode dispatch) that should be added.
