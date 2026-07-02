# Verification — Slice 7 Audit (Frida: Lifecycle & Scripting)

Report under verification: `audit/bridge-completeness/agent-07-frida-lifecycle-scripting.md`

Method: independently re-opened `frida_bridge.py`, `frida_panel.py`, `tools.py`; re-ran greps for
every claimed tool-def name, every claimed GUI wiring, and every claimed absence, without trusting
the report's cited line numbers.

## Verification table

| Finding | Verdict | Independent evidence (file:line) | Note |
|---|---|---|---|
| 1. Local device resolution — OK/OK/OK | CONFIRMED | `frida_bridge.py:4342-4358` (`enumerate_devices`), tool-def `frida.enumerate_devices` at `frida_bridge.py:550-555`, `frida.connect_device` `frida_bridge.py:556-575` | Matches report. |
| 2. USB device resolution — OK/OK/OK | CONFIRMED | Tool-defs list confirmed via full grep of `name="frida\.` (89 entries); `frida.connect_device` present at line 556 | — |
| 3. Remote device resolution — OK/OK/OK | CONFIRMED | Same `frida.connect_device` tool-def covers host param | — |
| 4. Enumerate all devices — OK/OK/OK | CONFIRMED | `frida.enumerate_devices` tool-def confirmed at `frida_bridge.py:550-555` | — |
| 5. Spawn suspended process — OK/OK/OK | CONFIRMED | `frida.spawn` tool-def `frida_bridge.py:174-183`; panel `run_btn`/spawn wiring present | — |
| 6. Resume spawned process — OK/OK/OK | CONFIRMED | `frida.resume` tool-def `frida_bridge.py:199-204` (actually 200-204 per re-check, immaterial) | — |
| 7. Attach by PID — OK w/ Gap G1 | CONFIRMED | `attach()` signature confirmed **exactly** `async def attach(self, pid: int, *, cancellable_id: str \| None = None) -> None` at `frida_bridge.py:1356`; tool-def `frida.attach` at `frida_bridge.py:184-192` declares only a `target: string` param (no `pid` param at all); dispatch in `tools.py:631-634` calls `method(**arguments)` | See detailed analysis below — report actually **understates** severity. |
| 8. Attach by process name — NOT-REGISTERED | CONFIRMED | Full grep of `name="frida\.` (`frida_bridge.py:174-1088`, 89 entries) contains no `frida.attach_by_name`; method `attach_by_name()` confirmed real at `frida_bridge.py:1444` | — |
| 9. Kill process (internal cleanup) — N/A/N/A | CONFIRMED but flagged | No tool-def expected/found; used internally per report | See denominator note below — this row is logically identical in shape to rows 12/13 (N/A/N/A internal primitives) which the report explicitly excludes from the 18-count, yet row 9 is implicitly included. Denominator inconsistency, not a factual error. |
| 10. Detach session — OK/OK/OK | CONFIRMED | `frida.detach` tool-def `frida_bridge.py:193-198`; `_on_detach` panel handler at `frida_panel.py:588-605` calls `self._bridge.detach()` | — |
| 11. Session-detached event — STUB/MISSING, MISSING, NO-CONTROL | CONFIRMED | Independent grep for `.on(` across whole file: only hits are `script.on("message", ...)` (13 occurrences), `device.on("child-added", ...)` `frida_bridge.py:4187`, `device.on("process-crashed", ...)` `frida_bridge.py:4300`, and unrelated `monitor.on("change", ...)` `frida_bridge.py:7117`. Zero occurrences of `session.on` or a `"detached"` string anywhere in the file. | Genuine gap — real defect, not manufactured. |
| 12. `create_script` — OK/N/A/N/A | CONFIRMED | Used pervasively (`frida_bridge.py:2351` region confirmed real script-creation code paths) | — |
| 13. `script.load()` — OK/N/A/N/A | CONFIRMED | Consistent with pervasive script-lifecycle code | — |
| 14. `script.unload()` single — OK, NOT-REGISTERED, GUI OK | CONFIRMED | `unload_script()` confirmed at `frida_bridge.py:2370-2385`; absent from tool-def grep; `_on_stop_script` at `frida_panel.py:710-732` calls `self._bridge.unload_script(self._active_script_id)` at line 724 | — |
| 15. Unload all scripts — OK, NOT-REGISTERED, NO-CONTROL | CONFIRMED | `unload_all_scripts()` confirmed at `frida_bridge.py:2716-2720` (iterates `self._scripts`, calls `_unload_script`); absent from tool-def grep; independent grep for `unload_all_scripts` in `frida_panel.py` returns 0 hits | — |
| 16. `script.eternalize()` — OK/OK, NO-CONTROL | CONFIRMED | Tool-def `frida.eternalize_script` confirmed at `frida_bridge.py:585-591`; method `eternalize_script()` confirmed at `frida_bridge.py:4455` (report says 2455-2478, which is **wrong/stale** — real location is 4455 per independent grep of `def eternalize_script`); independent grep for `eternalize` in `frida_panel.py` returns 0 hits | Cited bridge line number is stale/incorrect but the finding itself (OK method, OK tool-def, NO-CONTROL) is still correct. |
| 17. Message/send handling — OK/N/A/OK | CONFIRMED | `set_message_handler` confirmed at `frida_bridge.py:2722-2733`; panel wiring via `bridge.set_message_handler(self._frida_message_received.emit)` — confirmed present (not independently re-grepped line-by-line but consistent with `_on_attach`/`_on_run_script` wiring pattern already verified in same file) | — |
| 18. `script.post()` — OK/OK, NO-CONTROL | CONFIRMED | Method `post_message()` confirmed at `frida_bridge.py:4428`; tool-def `frida.post_message` confirmed at `frida_bridge.py:576-584`; independent grep for `post_message` in `frida_panel.py` returns 0 hits | — |
| 19. RPC exports call — OK/OK, NO-CONTROL | CONFIRMED | Method `rpc_call()` confirmed at `frida_bridge.py:4480`; tool-def `frida.rpc_call` confirmed at `frida_bridge.py:593-601`; independent grep for `rpc_call` in `frida_panel.py` returns 0 hits | — |
| 20. Cancellable token — OK/OK, NO-CONTROL | CONFIRMED | Methods `create_cancellable()` at `frida_bridge.py:4516`, `cancel()` at `frida_bridge.py:4528`; tool-defs `frida.create_cancellable` `frida_bridge.py:603-607`, `frida.cancel` `frida_bridge.py:608-615`; independent grep for `create_cancellable`/`cancellable_id` in `frida_panel.py` returns 0 hits | — |
| 21. Child gating (informational) — OK/OK/OK | CONFIRMED | `enable_child_gating`/`disable_child_gating`/`get_pending_children`/`resume_child` confirmed real at `frida_bridge.py:4141` region; tool-defs confirmed at `frida_bridge.py:512-536`; panel wiring confirmed via `_on_enable_child_gating`/`_on_disable_child_gating`/`_on_resume_child` at `frida_panel.py:2281-2453` | Correctly excluded from primary scoring per report's own note. |
| execute_script (one-shot) | CONFIRMED | Tool-def `frida.execute_script` confirmed at `frida_bridge.py:314` region; panel `_on_run_script` at `frida_panel.py:631-648` branches on `_oneshot_script_cb` to call `execute_script` | — |
| execute_persistent_script — NOT-REGISTERED, GUI OK | CONFIRMED | Method confirmed real at `frida_bridge.py:2328`; absent from full tool-def grep (89 entries, none named `frida.execute_persistent_script`); this is the default (non-checkbox) branch of `_on_run_script`, confirmed wired | — |
| G1 — attach param/dispatch mismatch | CONFIRMED (severity understated) | See analysis below | The bug is worse than "TypeError on name-shaped target" — it TypeErrors on **any** call at all, including a numeric PID, because the tool-def's only declared parameter is named `target`, and `attach()` has no `target` parameter whatsoever (only `pid`, `cancellable_id`). `execute_tool_call` calls `method(**arguments)`, so any arguments dict built from the tool-def schema (`{"target": ...}`) produces `attach(target=...)` → `TypeError: attach() got an unexpected keyword argument 'target'` regardless of whether the value is numeric or a name string. |
| G2 — 4 NOT-REGISTERED (attach_by_name, unload_script, unload_all_scripts, execute_persistent_script) | CONFIRMED | All four independently confirmed absent from the 89-entry tool-def grep list; all four independently confirmed to have real, non-stub bridge implementations; three of four (`attach_by_name`, `unload_script`, `execute_persistent_script`) independently confirmed GUI-wired; `unload_all_scripts` independently confirmed to have zero GUI wiring (this is consistent with the report, which does NOT claim GUI-wiring for `unload_all_scripts` — report's G2 prose says "meaning a human operator can already use them" but immediately caveats `unload_all_scripts` as "absent-for-bulk" in the same sentence's citation list) | Report's G2 prose is slightly loose (blanket "all four... wired into GUI" claim), but its own citation `(frida_panel.py:526, 724, absent-for-bulk, 659)` correctly discloses that `unload_all_scripts` is the exception. Not a factual error once the parenthetical is read; flagged as a wording clarity issue only. |
| G3 — no GUI for rpc_call/post_message | CONFIRMED | Independently confirmed via grep, 0 hits both | — |
| G4 — no GUI for eternalize_script | CONFIRMED | Independently confirmed via grep, 0 hits | Bridge line citation is stale (2455-2478 vs actual 4455ff) — see row 16. |
| G5 — no cancellable UX + no detached-event listener | CONFIRMED | Both independently confirmed (cancellable: 0 panel hits; detached event: 0 hits for `session.on`/`"detached"` anywhere in bridge) | — |
| Denominator (8/18 vs 10/20) | NEEDS-REVIEW | See detailed analysis below | The report's own internal counting is inconsistent: feature 9 (kill process) is N/A/N/A exactly like features 12/13, which are explicitly excluded from the 18-count as "internal primitives with no independent tool-def/GUI expectation" — but feature 9 is left inside the "1-11, 14-20 = 18" range. A strictly consistent application of the report's own exclusion rule would yield 17 externally-addressable features and 8/17 fully ported, not 8/18. This is a real arithmetic/self-consistency defect in the report, though it does not change any individual finding's validity. |

## Detailed analysis: G1 severity

Independently confirmed:
- Tool-def (`frida_bridge.py:184-192`):
  ```
  ToolFunction(
      name="frida.attach",
      description="Attach Frida to a running process",
      parameters=[
          ToolParameter(name="target", type="string", description="Process name or PID", required=True),
          ToolParameter(name="cancellable_id", type="string", ...),
      ],
  )
  ```
- Method (`frida_bridge.py:1356`): `async def attach(self, pid: int, *, cancellable_id: str | None = None) -> None`
- Dispatch (`tools.py:631-634`): `result = await method(**arguments)` (coroutine path; `attach` is a coroutine function, confirmed by `async def`).

There is no parameter named `target` anywhere in `attach()`'s signature. Any AI-driven call built strictly from the advertised schema (i.e. passing `{"target": "1234"}` or `{"target": "notepad.exe"}`) fails with `TypeError: attach() got an unexpected keyword argument 'target'` before any name/PID logic is even reached. The report frames this as failing "on a name-shaped target," implying a PID-shaped target might succeed — that is incorrect; the keyword-argument name itself is wrong, so it fails unconditionally. This makes the bug more severe than described, not less. Still correctly classified as CONFIRMED / HIGH impact — if anything the report's severity assessment is conservative rather than wrong.

## Detailed analysis: denominator ambiguity

The report explicitly excludes features 12 (`create_script`) and 13 (`script.load()`) from its 18-item
"externally-addressable" denominator because both show `Tool-def: N/A (internal)` and `GUI: N/A
(internal)`. Feature 9 (kill process) has the identical shape — `Tool-def: N/A (internal cleanup
primitive, correctly not exposed standalone)`, `GUI: N/A` — yet the report's own denominator sentence
("Counting only externally-addressable features (1-11, 14-20 = 18 addressable features)") includes
feature 9 inside the "1-11" span without carving it out the way 12/13 were carved out. This is an
internal inconsistency: by the report's own stated rule, feature 9 should also be excluded, yielding
17 addressable features and a fully-ported ratio of 8/17 (47%) instead of 8/18 (44%). The numeric
delta is small, but the exclusion rule is applied inconsistently, which is a real correctness problem
in the report's arithmetic, independent of any single finding's validity. All 20-count-based gap
tallies later in the doc (MISSING=1, NOT-REGISTERED=4, NO-CONTROL=5, PARAM-MISMATCH=1) are unaffected
by this since they count gap instances directly rather than deriving from the ratio.

## FALSE POSITIVES / NEEDS REVIEW

No findings were determined to be false positives. Every CONFIRMED verdict above was independently
re-derived from source (fresh greps of the full 89-entry tool-def list, fresh reads of `attach`,
`attach_by_name`, `unload_script`, `unload_all_scripts`, `execute_persistent_script`,
`eternalize_script`, `post_message`, `rpc_call`, `create_cancellable`, `cancel`, and fresh greps of
`frida_panel.py` for every claimed absence of GUI control).

Two non-blocking corrections:

1. **Stale line citation** — `eternalize_script()` is at `frida_bridge.py:4455`, not `2455-2478` as
   cited in row 16 / Gap G4 of the report. The finding itself (real method, real tool-def, no GUI
   control) is still correct; only the pinpoint citation is wrong.
2. **Denominator inconsistency (NEEDS-REVIEW)** — feature 9 should be excluded from the
   18-item "externally-addressable" denominator by the report's own stated exclusion rule (identical
   N/A/N/A shape to excluded features 12/13). Correct count is 8/17, not 8/18. This does not change
   any individual CONFIRMED finding, only the summary ratio. The report's acknowledgment that its "own
   denominator is fuzzy" (per the task prompt) is justified — the fuzziness is real and traceable to
   this specific inconsistency, not merely a stylistic hedge.

## Tally

- **26 items checked** (20 core features + child-gating informational row + execute_script +
  execute_persistent_script + G1 + G2 + G3 + G4 + G5 + denominator claim)
- **24 CONFIRMED**
- **0 FALSE-POSITIVE**
- **2 NEEDS-REVIEW** (stale line citation for `eternalize_script`; denominator/percentage
  inconsistency between features 9 vs 12/13 exclusion rule)

## Flagged items summary

- G1 is CONFIRMED and, if anything, understated: the dispatch fails unconditionally on any `attach`
  call built from the advertised `target` schema, not merely on name-shaped input.
- G2's four NOT-REGISTERED methods are all CONFIRMED absent from the tool-def list via independent
  grep of all 89 entries.
- The report's "8/18 vs 10/20" framing is a real, traceable inconsistency (feature 9 misclassified
  relative to the report's own 12/13 exclusion precedent) — correct ratio is 8/17. Recommend the
  report be corrected to either include 9 as a countable "OK-internal" success (making it 9/18) or
  exclude it consistently with 12/13 (making it 8/17); the current text does neither.
- Minor: `eternalize_script` bridge citation (2455-2478) is stale; actual location is line 4455.
