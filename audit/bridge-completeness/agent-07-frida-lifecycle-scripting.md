# Slice 7 Audit — Frida: Lifecycle & Scripting

Bridge: `src/intellicrack/bridges/frida_bridge.py` (7146 lines)
Panel: `src/intellicrack/ui/panels/frida_panel.py` (2505 lines)
Dispatch: `src/intellicrack/core/tools.py::ToolRegistry.execute_tool_call` (getattr dispatch, `src/intellicrack/core/tools.py:551-654`)

Scope: spawn/attach/resume/detach, device/session management, script load/unload, RPC exports,
message/send handling. Excludes Interceptor/Stalker/Memory-scan/NativeFunction/module-enumeration
(different slice), except where a lifecycle primitive (e.g. `execute_script`) is the mechanism used
to deliver instrumentation scripts.

## Native ground truth (Frida Python API — device/session/script lifecycle surface)

Sourced from Frida's public Python API surface (`frida` top-level functions, `frida.core.Device`,
`frida.core.Session`, `frida.core.Script`) per frida-python docs/DeepWiki and community references
(see Sources).

1. `frida.get_local_device()` / device resolution (local)
2. `frida.get_usb_device()` (USB device resolution)
3. `frida.get_device_manager().add_remote_device(host)` (remote device resolution)
4. `frida.enumerate_devices()` (list all devices)
5. `device.spawn(program, argv=...)` (spawn suspended process)
6. `device.resume(pid)` (resume a spawned/suspended process)
7. `device.attach(pid_or_name)` — attach by PID
8. attach by process name (name→PID resolution, then attach)
9. `device.kill(pid)` (kill spawned/target process) — lifecycle cleanup primitive
10. `session.detach()` (detach from a session)
11. `session.on("detached", callback)` (session-detached event)
12. `session.create_script(source)` (compile/load a script into session)
13. `script.load()` (activate a loaded script)
14. `script.unload()` (tear down a single script)
15. bulk/all-scripts teardown (application-level convenience, not a single native call but standard
    lifecycle housekeeping expected of any Frida integration)
16. `script.eternalize()` (detach script from Python lifetime, keep running in target)
17. `script.on("message", callback)` (message/send handling — receive `send()`/`console.log`/error
    payloads from the injected script)
18. `script.post(message, data=None)` (post message from Python into the running script)
19. `script.exports_sync` / `script.exports_async` (RPC — call `rpc.exports` functions exposed by the
    script)
20. `frida.Cancellable()` + cancellable-token propagation to spawn/attach (cancel long-running
    operations)
21. `device.enumerate_pending_children()` / spawn-gating child lifecycle (own slice? — child-gating is
    borderline instrumentation; included here only as it affects spawn lifecycle of *child* processes)

Features 21 (child gating) is arguably shared with the instrumentation slice; it is noted but not
scored in the coverage matrix below since it is about children of an instrumented process, not the
core session lifecycle. Everything else (1-20) is the actual denominator for this audit (N=20).

## Coverage matrix

| # | Native feature | Bridge method (file:line) | Tool-def | GUI control |
|---|---|---|---|---|
| 1 | Local device resolution | OK — `initialize()` `frida_bridge.py:1190-1218` (`frida.get_local_device`), also `_resolve_frida_device` `frida_bridge.py:4360-4378` | N/A (internal, invoked by `connect_device`) | OK — device combo defaults to `local`, `frida_panel.py:127` |
| 2 | USB device resolution | OK — `_resolve_frida_device` `frida_bridge.py:4374-4375` (`frida.get_usb_device`) | OK — `frida.connect_device` `frida_bridge.py:556-575` (device_type param) | OK — `_on_device_changed` recognizes `"usb"` text, `frida_panel.py:939-940` |
| 3 | Remote device resolution | OK — `_resolve_frida_device` `frida_bridge.py:4376-4378` (`manager.add_remote_device`) | OK — `frida.connect_device` `frida_bridge.py:556-575` (host param) | OK — `_on_device_changed` parses `"remote:<host>"`, `frida_panel.py:936-938` |
| 4 | Enumerate all devices | OK — `enumerate_devices()` `frida_bridge.py:4342-4358` | OK — `frida.enumerate_devices` `frida_bridge.py:550-555` | OK — `_on_refresh_devices` path populates combo, `frida_panel.py:1207-1235` (`_populate_device_combo`) |
| 5 | Spawn suspended process | OK — `spawn()` `frida_bridge.py:1523-1600` (real: builds argv, spawns via cancellable thread call, auto-attaches, registers with `ProcessManager`, rolls back/kills on post-spawn attach failure) | OK — `frida.spawn` `frida_bridge.py:174-183` | OK — Spawn button + path/args fields, `frida_panel.py:144`, `_on_spawn` `frida_panel.py:1249-1276` |
| 6 | Resume spawned process | OK — `resume()` `frida_bridge.py:1650-1672` | OK — `frida.resume` `frida_bridge.py:199-204` | OK — Resume button, `frida_panel.py:145`, `_on_resume` `frida_panel.py:1302-1320` |
| 7 | Attach by PID | OK — `attach()` `frida_bridge.py:1356-1407` (real: resolves device, cancellable, structured error mapping for `ProcessNotFoundError`/`PermissionDeniedError`/`TransportError`/`InvalidArgumentError`) | OK — `frida.attach` `frida_bridge.py:184-192` — **but see Gap G1**: tool-def param is `target` (string, "Process name or PID") while `attach(pid: int, ...)` only accepts an int PID; dispatch (`tools.py:587-588` `getattr(bridge, "attach")`) will TypeError on a name-shaped `target` | OK — Attach button, numeric branch of `_on_attach`, `frida_panel.py:521-522, 537-546` |
| 8 | Attach by process name | OK — `attach_by_name()` `frida_bridge.py:1444-1521` (real: enumerates processes, resolves name→PID, structured error mapping) | **NOT-REGISTERED** — no `frida.attach_by_name` ToolFunction entry exists (full grep of `name="frida\.` list, `frida_bridge.py:174-1088`, confirms absence); unreachable via `tool_definition`/AI routing, though still callable through the generic `execute_tool_call` getattr path since the method exists on the bridge | OK — non-numeric branch of `_on_attach`, `frida_panel.py:523-534` |
| 9 | Kill process (spawn-owned cleanup) | OK — used internally: `_shutdown_spawned_process` `frida_bridge.py:1316-1327`, `_perform_detach` `frida_bridge.py:1727-1736`, spawn rollback `frida_bridge.py:1589-1595` | N/A (internal cleanup primitive, correctly not exposed standalone) | N/A |
| 10 | Detach session | OK — `detach()` `frida_bridge.py:1674-1700` / `_perform_detach()` `frida_bridge.py:1702-1746` (unloads all scripts first, then detaches, optional spawn-kill, resets state) | OK — `frida.detach` `frida_bridge.py:193-198` | OK — Detach button, `frida_panel.py:140`, `_on_detach` `frida_panel.py:588-605` |
| 11 | Session-detached event | **STUB/MISSING** — no `session.on("detached", ...)` registration found anywhere in `frida_bridge.py` (grep for `"detached"` and `session.on` yields no hits); the bridge only detects detach through its own explicit `detach()` call, not through Frida's async detached-signal (e.g., target process crash won't be observed) | MISSING (no method to register) | NO-CONTROL |
| 12 | `create_script` (compile/load JS into session) | OK — used pervasively, e.g. `frida_bridge.py:2351` (persistent script), `frida_bridge.py:3826-3856` (`_create_script_with_cancellable` helper) | N/A (internal primitive, surfaced via `execute_script`/`execute_persistent_script`) | N/A |
| 13 | `script.load()` | OK — `frida_bridge.py:2364` (persistent script path) and equivalents throughout instrumentation helpers | N/A (internal) | N/A |
| 14 | `script.unload()` (single) | OK — `unload_script()` `frida_bridge.py:2370-2385` delegates to private `_unload_script()` `frida_bridge.py:2649-2685` | **NOT-REGISTERED** — no `frida.unload_script` ToolFunction entry (grep confirms absence) | OK — Stop button, `_on_stop_script` `frida_panel.py:710-732` |
| 15 | Unload all scripts (bulk) | OK — `unload_all_scripts()` `frida_bridge.py:2716-2720`, iterates `self._scripts` calling `_unload_script` | **NOT-REGISTERED** — no `frida.unload_all_scripts` ToolFunction entry | **NO-CONTROL** — no button/menu action found in panel (grep for `unload_all_scripts` in `frida_panel.py` returns 0 hits); only per-script Stop exists |
| 16 | `script.eternalize()` | OK — `eternalize_script()` `frida_bridge.py:2455-2478` (real: unloads bookkeeping entry, calls `script.eternalize`) | OK — `frida.eternalize_script` `frida_bridge.py:585-592` | **NO-CONTROL** — no button/action found in panel (grep for `eternalize` in `frida_panel.py` returns 0 hits) |
| 17 | Message/send handling (`script.on("message")`) | OK — pervasive `on_message` closures forwarding to `_dispatch_message()` `frida_bridge.py:2735-2747`, plus public `set_message_handler()` `frida_bridge.py:2722-2733` | N/A (message reception is push-based via callback, not a request/response tool call; `set_message_handler` is the registration hook) | OK — `set_bridge()` wires `bridge.set_message_handler(self._frida_message_received.emit)` `frida_panel.py:470`; rendered in `_on_frida_message` `frida_panel.py:490-503` |
| 18 | `script.post()` (Python→script message) | OK — `post_message()` `frida_bridge.py:4428-4453` (real: validates script exists, parses JSON, posts) | OK — `frida.post_message` `frida_bridge.py:576-584` | **NO-CONTROL** — no button/input for posting a message to a running script found in panel (grep for `post_message` in `frida_panel.py` returns 0 hits) |
| 19 | RPC exports call (`exports_sync`) | OK — `rpc_call()` `frida_bridge.py:4480-4514` (real: resolves `script.exports_sync.<method>`, validates callable, structured error) | OK — `frida.rpc_call` `frida_bridge.py:593-602` | **NO-CONTROL** — no button/dialog for invoking an RPC export found in panel (grep for `rpc_call` in `frida_panel.py` returns 0 hits) |
| 20 | Cancellable token creation/cancel | OK — `create_cancellable()` `frida_bridge.py:4516-4526`, `cancel()` `frida_bridge.py:4528-4544ff` (real: builds `frida.Cancellable`, tracked in `self._cancellables`, consumed by `attach`/`attach_by_name`/`spawn` via `_resolve_cancellable`) | OK — `frida.create_cancellable` `frida_bridge.py:603-608`, `frida.cancel` `frida_bridge.py:609-616` | **NO-CONTROL** — no "Cancel operation" button/action in panel; long-running Attach/Spawn calls are fired without ever creating/passing a cancellable_id (grep for `create_cancellable`/`cancellable_id` in `frida_panel.py` returns 0 hits) |
| 21 (informational, not scored) | Spawn/child gating (children of instrumented process) | OK — `enable_child_gating`/`disable_child_gating`/`get_pending_children`/`resume_child`, `frida_bridge.py:4141-4249` | OK — registered | OK — wired `frida_panel.py:2281-2456` | — out of core-20 scoring; belongs partly to instrumentation slice, noted only for completeness |

Additionally verified as real (not relevant to native-feature denominator, but part of "script
load/unload" surface used by lifecycle): `execute_script()` (one-shot, `frida_bridge.py:2301-2326`,
wired via "one-shot" checkbox `frida_panel.py:645-655`) and `execute_persistent_script()`
(`frida_bridge.py:2328-2368`, NOT-REGISTERED as a tool-def — see Gap G2 below — but fully wired in
GUI as the default (non-one-shot) Run-script path, `frida_panel.py:658-667`).

## Coverage summary

- **20 core native features scored** (feature 21 child-gating tracked informationally, already fully
  ported and out of this slice's primary scope).
- **Fully ported (all three layers OK): 10 / 20** — features 1, 2, 3, 4, 5, 6, 10, 12(N/A-internal),
  13(N/A-internal) excluded from "3-layer" count since they're internal primitives with no
  independent tool-def/GUI expectation. Counting only externally-addressable features (1-11, 14-20 =
  18 addressable features): **fully ported = 8 / 18** (features 1, 2, 3, 4, 5, 6, 10, 17).
- **Gap counts by type** (across the 18 externally-addressable features, plus the 2 extra
  script-execution methods called out above = 20 gap-scored items):
  - MISSING (native capability with no bridge implementation): **1** — session `"detached"` event
    listener (feature 11).
  - STUB: **0**
  - NOT-REGISTERED (bridge method real, no tool-def): **4** — `attach_by_name` (feature 8),
    `unload_script` (feature 14), `unload_all_scripts` (feature 15), `execute_persistent_script`
    (script-execution surface, called out above).
  - NO-CONTROL (no GUI wiring at all): **4** — `unload_all_scripts` (feature 15),
    `eternalize_script` (feature 16), `post_message` (feature 18), `rpc_call` (feature 19),
    plus `create_cancellable`/`cancel` (feature 20) = **5** total NO-CONTROL instances.
  - DEAD-CONTROL: **0** (every GUI control found does invoke a real, existing bridge method).
  - PARAMETER/DISPATCH MISMATCH (new category, not in original enum but material): **1** —
    `frida.attach` tool-def accepts a name-or-PID `target` string but the bound method only accepts
    `pid: int` (Gap G1).

## Prioritized gap list

1. **G1 — `frida.attach` tool-def/dispatch mismatch (HIGH impact).** The registered `ToolFunction`
   for `frida.attach` (`frida_bridge.py:184-192`) advertises a `target` parameter documented as
   "Process name or PID", but `execute_tool_call` (`tools.py:587-588`) dispatches straight to
   `FridaBridge.attach(self, pid: int, ...)` (`frida_bridge.py:1356`), which has no name-resolution
   logic (that lives only in `attach_by_name`, a sibling method). Any AI/orchestration-driven call to
   `frida.attach` with a process name will fail with a TypeError, silently misrepresenting the tool's
   real capability. Fix belongs in `src/intellicrack/bridges/frida_bridge.py`: either (a) register
   `frida.attach_by_name` as its own tool-def and correct `frida.attach`'s description/param to
   `pid: integer` only, or (b) make `attach()` accept `str | int` and internally dispatch to
   `attach_by_name` when given a non-numeric string — but per project rules "NEVER delete method
   bindings," so the safer path is (a): add the missing tool-def and tighten `frida.attach`'s
   documented contract.

2. **G2 — `attach_by_name`, `unload_script`, `unload_all_scripts`, `execute_persistent_script` are
   NOT-REGISTERED (HIGH impact).** All four are real, fully wired into the GUI (`frida_panel.py:526`,
   `724`, absent-for-bulk, `659`), meaning a human operator can already use them — but they are
   invisible to AI-driven orchestration because `_FRIDA_FUNCTIONS` (`frida_bridge.py:173-1096`, the
   list backing `tool_definition`) has no entries for them. This is the single biggest "AI can't do
   what the human GUI can do" gap in this slice. Fix belongs in
   `src/intellicrack/bridges/frida_bridge.py`: add four `ToolFunction` entries to `_FRIDA_FUNCTIONS`
   (`frida.attach_by_name`, `frida.unload_script`, `frida.unload_all_scripts`,
   `frida.execute_persistent_script`), mirroring the parameter/return shape already documented in each
   method's docstring.

3. **G3 — No GUI affordance for RPC exports or Python→script `post_message` (MEDIUM impact).**
   `rpc_call()` (`frida_bridge.py:4480-4514`) and `post_message()` (`frida_bridge.py:4428-4453`) are
   both real, both registered as tool-defs, but have zero GUI controls — a human user of the Frida
   panel cannot invoke an `rpc.exports` function or push a message into a running persistent script at
   all; only the AI-orchestration path can reach them. Given the product's "coherent single GUI"
   design goal (per CLAUDE.md), this is a real usability gap. Fix belongs in
   `src/intellicrack/ui/panels/frida_panel.py`: add a small "RPC / Messaging" control group next to
   the script console (method-name + JSON-args input calling `rpc_call`, and a raw-JSON input calling
   `post_message`), following the existing `run_bridge_coroutine_logged` pattern used throughout the
   file.

4. **G4 — `eternalize_script` has no GUI control (MEDIUM-LOW impact).** Real bridge method
   (`frida_bridge.py:2455-2478`) and tool-def (`frida_bridge.py:585-592`) exist, but there is no way
   for a GUI user to eternalize the currently active persistent script (only Stop/unload is exposed).
   Fix belongs in `src/intellicrack/ui/panels/frida_panel.py`: add an "Eternalize" button beside the
   existing Stop button (`frida_panel.py:144` area) wired to `self._bridge.eternalize_script(self._active_script_id)`.

5. **G5 — No cancellable-token UX and no session-detached event listener (LOW-MEDIUM impact).**
   `create_cancellable`/`cancel` (`frida_bridge.py:4516-4544`) are real and registered but never used
   by the panel — long Attach/Spawn calls (`frida_panel.py:521-546`, `1265-1276`) never create or pass
   a `cancellable_id`, so a user has no way to abort a hung attach/spawn from the GUI. Separately, the
   bridge never registers a Frida `session.on("detached", ...)` callback, so an externally-terminated
   target (crash, kill -9 from outside) leaves `self.state.process_attached` stale until the user
   manually detaches. Fix for cancellables belongs in `frida_panel.py` (wire a Cancel button that
   calls `create_cancellable` before Attach/Spawn and `cancel` on user abort); fix for the
   detached-event gap belongs in `frida_bridge.py::_perform_attach`/`_post_spawn_attach`
   (`frida_bridge.py:1409-1442`, `1602-1648`) to register `session.on("detached", ...)` and update
   `self.state`/publish accordingly.

## Sources

- [Python Examples of frida.get_device](https://www.programcreek.com/python/example/111316/frida.get_device)
- [frida/frida-python | DeepWiki](https://deepwiki.com/frida/frida-python)
- [Frida cheat sheet](https://awakened1712.github.io/hacking/hacking-frida/)
