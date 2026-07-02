# Verification of remediation — Slice 10: SANDBOX + PROCESS

Read-only, adversarial re-check of every row the original audit
(`audit/bridge-completeness/agent-10-sandbox-process.md`) and its verifier
(`audit/bridge-completeness/verify/agent-10-sandbox-process-verification.md`)
marked as NOT fully OK/OK/OK. Every citation below is a fresh `rg`/`Read`
against the live source (not copied from either prior report), plus one
empirical dispatch check through `ToolRegistry.execute_tool_call` for the
capability-gate concern on `sandbox.stop`.

Denominator: the 21 previously-non-OK rows — SANDBOX: S2, S9, S12, S14, S16,
S19, S21, S28, S29 (9 rows). PROCESS: P13, P20, P25, P26, P29, P38, P39, P42,
P43, P47, P48, P49, P55, P56, P57, P58, P62, P63, P64, P65, P66 (21 rows,
counting P47-P49 and P56-P58 individually as NO-CONTROL-but-registered per
the original matrix).

---

## SANDBOX re-verification

| # | Feature | Prior verdict | Re-check result | Evidence |
|---|---|---|---|---|
| S2 | Configure VM timeout/network/memory | DEAD-CONTROL | **FIXED — OK/OK/OK** | L1/L2 unchanged: `create()` sandbox_bridge.py:1043-1050 (`timeout_seconds`, `network_enabled`, `memory_limit_mb` params), tool-def sandbox_bridge.py:410-430. L3: `sandbox_panel.py:191-238` `_build_config_row` adds `QSpinBox` (`_timeout_spin`, range 1-86400s), `QSpinBox` (`_memory_limit_spin`, range 128-131072MB), `QCheckBox` (`_network_enabled_check`); `sandbox_panel.py:586-599` `_sandbox_create_config()` reads all three into a `_SandboxCreateConfig` TypedDict; `_on_create` (sandbox_panel.py:601-623) and `_on_restart`'s create path (sandbox_panel.py:737-756) both call `self._bridge.create(sandbox_type=sandbox_type, **config)`. Verified `create()`'s signature (process_bridge.py — actually sandbox_bridge.py:1043-1049) accepts exactly these three kwargs with matching names/types. |
| S9 | List all sandbox instances (standalone) | NO-CONTROL | **STILL NO-CONTROL** | `list()` sandbox_bridge.py:1415, tool-def `sandbox.list` sandbox_bridge.py:583. `rg "self\._bridge\.list\(" sandbox_panel.py` → zero matches. Instances tree is still populated exclusively from `status()` (sandbox_panel.py `_poll_status`). Untouched by this remediation pass. |
| S12 | List snapshots | NO-CONTROL | **STILL NO-CONTROL** | `snapshot_list()` sandbox_bridge.py:1526, tool-def `sandbox.snapshot_list` sandbox_bridge.py:627. Zero call sites in sandbox_panel.py. Snapshots tree still populated only by manual row append/removal on create/delete success callbacks, never refreshed from `snapshot_list()`. |
| S14 | Pause running QEMU VM (`sandbox.stop`) | NOT-REGISTERED (GUI-wired) | **FIXED — OK/OK/OK, capability-gate concern investigated and cleared** | L1: `stop(instance_id)` sandbox_bridge.py:1620-1643 (real QMP `qmp.stop()`). L2: new `ToolFunction(name="sandbox.stop", ...)` sandbox_bridge.py:658-670, single `instance_id: string, required=True` param matching the method signature exactly. L3: `_on_pause_vm` sandbox_panel.py (`self._bridge.stop(self.sandbox_id)`), unchanged and still wired. **Capability-gate check**: `TOOL_CAPABILITY_MAP` (bridges/base.py) contains both a bare `"stop": "debugging"` entry (line 87, shared with x64dbg/Frida) AND an explicit `"sandbox.stop": "dynamic_analysis"` entry (line 152). `core/tools.py:679` resolves capability via `TOOL_CAPABILITY_MAP.get(function_name) or TOOL_CAPABILITY_MAP.get(attr_name)` — the full `"sandbox.stop"` key is checked FIRST and matches, so the bare `"stop"`→`"debugging"` fallback is never reached. `SandboxBridge.__init__` sets `supports_dynamic_analysis=True` (sandbox_bridge.py:248). Empirically confirmed live: `sandbox_bridge.capabilities.has_capability("debugging")` → `False`, `has_capability("dynamic_analysis")` → `True`; `TOOL_CAPABILITY_MAP.get("sandbox.stop")` → `"dynamic_analysis"` (not the bare-`"stop"` fallback). A dedicated regression test (`tests/test_bridge_completeness/sandbox-process/test_sandbox_l1_l2.py:331-367`, `test_execute_tool_call_dispatches_stop_to_real_method`) exercises the exact same collision scenario end-to-end through `ToolRegistry.execute_tool_call` and asserts the real QMP `stop()` call fires — this is a real, falsifiable gate for the concern. **Not capability-gate-blocked.** |
| S16 | Retrieve pending QEMU guest-agent messages | NO-CONTROL | **STILL NO-CONTROL** | `get_pending_messages()` sandbox_bridge.py:1727, tool-def sandbox_bridge.py:685. Zero call sites in sandbox_panel.py. |
| S19 | Stop network capture (cleanup variant, `stop_pcap`) | NOT-REGISTERED (GUI-wired) | **FIXED — OK/OK/OK** | L1: `stop_pcap(instance_id)` sandbox_bridge.py:1874-1918 (delegates to `pcap_stop`, tolerant no-op). L2: new `ToolFunction(name="sandbox.stop_pcap", ...)` sandbox_bridge.py:736-751, single `instance_id: string, required=True` matching the method. L3: `_cleanup()` sandbox_panel.py:335 calls `run_bridge_coroutine(self._bridge.stop_pcap(self.sandbox_id))`, unchanged and still wired. `stop_pcap` is not in `TOOL_CAPABILITY_MAP` under any key (grep confirms), so no gate applies. Regression test at `test_sandbox_l1_l2.py:370-383` (`test_execute_tool_call_dispatches_stop_pcap_to_real_method`) dispatches through the registry and asserts the real no-op/stop outcome. |
| S21 | Apply anti-evasion hardening profile | NO-CONTROL | **STILL NO-CONTROL** | `anti_evasion()` sandbox_bridge.py:2006, tool-def sandbox_bridge.py:773. Zero call sites in sandbox_panel.py. |
| S28 | C2 communication pattern detection | NO-CONTROL | **STILL NO-CONTROL** | `detect_c2()` sandbox_bridge.py:2392, tool-def sandbox_bridge.py:929. Zero call sites in sandbox_panel.py. |
| S29 | Diff two execution reports | NO-CONTROL | **STILL NO-CONTROL** | `diff()` sandbox_bridge.py:2438, tool-def sandbox_bridge.py:942. Zero call sites in sandbox_panel.py. |

SANDBOX: **3 of 9 fixed** (S2, S14, S19). **6 of 9 unchanged / still broken**
(S9, S12, S16, S21, S28, S29 — all NO-CONTROL, zero GUI wiring added; the
`sandbox_panel.py` diff for this remediation pass touches only the
`_build_config_row`/`_sandbox_create_config` machinery for S2 and adds no
new call sites for any of these six methods, confirmed by an exhaustive
`rg "self\._bridge\.(list|snapshot_list|get_pending_messages|anti_evasion|detect_c2|diff)\("`
over the full file returning zero matches).

---

## PROCESS re-verification

| # | Feature | Prior verdict | Re-check result | Evidence |
|---|---|---|---|---|
| P13 | Decommit memory region | NOT-REGISTERED + NO-CONTROL | **FIXED — OK/OK/OK** | L1: `decommit_memory(pid, address, size)` process.py:7049 (real `VirtualFreeEx(MEM_DECOMMIT)`, unchanged). L2: new `ToolFunction(name="process.decommit_memory", ...)` process.py:654-662, three required params `pid:int`, `address:int`, `size:int` — matches the method signature exactly. Not in `TOOL_CAPABILITY_MAP` — no gate. L3: `memory_tab.py:288-303` adds `_decommit_size` `QSpinBox` + "Decommit" button wired to `_on_decommit` (memory_tab.py:682-742), which parses the address field, confirms via `QMessageBox`, and calls `self._bridge.decommit_memory(pid, addr, size)` through `run_bridge_coroutine_logged` (memory_tab.py:722), removing the matching row from the allocation log on success. |
| P20 | Get process working-set memory (MB), standalone | NO-CONTROL (subsumed) | **STILL NO-CONTROL, unchanged from audit** | `get_process_memory_mb(pid)` process.py:2183, tool-def process.py:713 (pre-existing, already registered before this remediation). `rg "self\._bridge\.get_process_memory_mb\(" process_panel/` → zero matches; still only called internally from `list_processes_detailed`'s aggregate loop (process.py:2066-2068). This row was already OK/registered at L2 before remediation — the only gap was L3, and no L3 control was added. Note: this row was L2-complete already; the plan's Wave 2/Agent F scope was "register the 13 NOT-REGISTERED methods," and P20 was never one of the 13 (it was NO-CONTROL only), so it was correctly out of scope for L2 work but was also not picked up in the L3 wave. |
| P25 | Enumerate handles (raw, system-wide, no type resolution) | NOT-REGISTERED + NO-CONTROL | **L1/L2 FIXED, L3 still NO-CONTROL** | L1: `enumerate_handles(pid=None)` process.py:6434 (unchanged, real). L2: new `ToolFunction(name="process.enumerate_handles", ...)` process.py:766-773, one optional param `pid: integer, required=False` — matches signature `pid: int | None = None`. No capability gate. L3: `rg "self\._bridge\.enumerate_handles\(" process_panel/` → zero matches. Still redundant-but-orphan from the GUI's perspective (GUI still uses `get_handles`/P24 exclusively). **Row remains not fully OK/OK/OK** (L3 absent). |
| P26 | Enumerate handles (system-wide, type-resolved, cached) | NOT-REGISTERED + NO-CONTROL | **L1/L2 FIXED, L3 still NO-CONTROL** | L1: `enum_handles(pid=None)` process.py:4499 (unchanged, real). L2: new `ToolFunction(name="process.enum_handles", ...)` process.py:774-781, matches signature. No capability gate. L3: `rg "self\._bridge\.enum_handles\(" process_panel/` → zero matches. **Row remains not fully OK/OK/OK.** |
| P29 | Enumerate services (by active/inactive state) | NOT-REGISTERED + NO-CONTROL | **L1/L2 FIXED, L3 still NO-CONTROL** | L1: `enumerate_services(*, active=False)` process.py:6663 (unchanged, real). L2: new `ToolFunction(name="process.enumerate_services", ...)` process.py:798-805, one optional `active: boolean` param — matches keyword-only `active: bool = False`. No capability gate. L3: `rg "self\._bridge\.enumerate_services\(" process_panel/` → zero matches; GUI still calls only `list_services` (P28). **Row remains not fully OK/OK/OK.** |
| P38 | Process mitigation policies (simplified flat schema, singular) | NOT-REGISTERED + NO-CONTROL | **L1/L2 FIXED, L3 still NO-CONTROL** | L1: `get_mitigation_policy(pid=None)` process.py:7235 (unchanged, real, distinct SEHOP-mask query). L2: new `ToolFunction(name="process.get_mitigation_policy", ...)` process.py:871-878, one optional `pid: integer` param — matches. No capability gate. L3: `rg "self\._bridge\.get_mitigation_policy\(" process_panel/` (word-boundary-safe against the plural) → zero matches; GUI's `_refresh_mitigations` still calls only the plural `get_mitigation_policies`. **Row remains not fully OK/OK/OK.** |
| P39 | Extension-point-disable mitigation policy | NOT-REGISTERED + NO-CONTROL | **L1/L2 FIXED, L3 still NO-CONTROL** | L1: `get_extension_policy(pid=None)` process.py:7304 (unchanged, real). L2: new `ToolFunction(name="process.get_extension_policy", ...)` process.py:879-885, matches signature. No capability gate. L3: `rg "self\._bridge\.get_extension_policy\(" process_panel/` → zero matches. **Row remains not fully OK/OK/OK.** |
| P42 | Read from named pipe | DEAD-CONTROL | **FIXED — OK/OK/OK** | L1: `pipe_read(handle, size)` process.py:7587 (unchanged, real). L2: tool-def `process.pipe_read` process.py:849 (pre-existing, unchanged). L3: `system_tab.py:357-378` adds a `_pipe_read_size` `QSpinBox` + "Read" button wired to `_on_pipe_read` (system_tab.py:963-993), which resolves the selected pipe via the new shared `_selected_pipe()` helper (system_tab.py:893-912) and calls `self._bridge.pipe_read(handle, size)` through `run_bridge_coroutine_logged`, rendering the hex result into `_pipe_io_data`. |
| P43 | Write to named pipe | DEAD-CONTROL | **FIXED — OK/OK/OK** | L1: `pipe_write(handle, data)` process.py:7614 (unchanged, real). L2: tool-def `process.pipe_write` process.py:858 (pre-existing, unchanged). L3: `system_tab.py:379-382` adds a "Write" button wired to `_on_pipe_write` (system_tab.py:995-1023), which parses hex text from `_pipe_io_data`, resolves the selected pipe via `_selected_pipe()`, and calls `self._bridge.pipe_write(handle, data)` through `run_bridge_coroutine_logged`. |
| P47 | Open device handle | Registered, NO-CONTROL | **STILL NO-CONTROL, unchanged** | `device_open()` process.py:8170, tool-def process.py:891 (both pre-existing/unchanged). `rg "device_open\(" process_panel/` → zero matches. No GUI added. |
| P48 | Send IOCTL to device | Registered, NO-CONTROL | **STILL NO-CONTROL, unchanged** | `device_ioctl()` process.py:8206, tool-def process.py:899. Zero GUI call sites. |
| P49 | Close device handle | Registered, NO-CONTROL | **STILL NO-CONTROL, unchanged** | `device_close()` process.py:8267, tool-def process.py:910. Zero GUI call sites. |
| P55 | Read registry value (hive+key+value form) | NOT-REGISTERED + NO-CONTROL | **L1/L2 FIXED, L3 still NO-CONTROL** | L1: `read_registry(hive, key_path, value_name)` process.py:7095 (unchanged, real). L2: new `ToolFunction(name="process.read_registry", ...)` process.py:998-1012, three required params `hive:string`, `key_path:string`, `value_name:string` — matches signature exactly. No capability gate. L3: `rg "self\._bridge\.read_registry\(" process_panel/` → zero matches; GUI still uses only `reg_read_value` (P52). **Row remains not fully OK/OK/OK.** |
| P56 | Create memory-mapped section object | Registered, NO-CONTROL | **STILL NO-CONTROL, unchanged** | `create_section()` process.py:8965, tool-def process.py:959. Zero GUI call sites. |
| P57 | Map section into process | Registered, NO-CONTROL | **STILL NO-CONTROL, unchanged** | `map_section()` process.py:9055, tool-def process.py:968. Zero GUI call sites. |
| P58 | Unmap section | Registered, NO-CONTROL | **STILL NO-CONTROL, unchanged** | `unmap_section()` process.py:1619, tool-def process.py:977. Zero GUI call sites. |
| P62 | Enumerate all system processes (dict form) | NOT-REGISTERED + NO-CONTROL | **L1/L2 FIXED, L3 still NO-CONTROL** | L1: `enumerate_system_processes()` process.py:6366 (unchanged, real). L2: new `ToolFunction(name="process.enumerate_system_processes", ...)` process.py:554-559, zero params — matches the no-arg signature. No capability gate. L3: `rg "self\._bridge\.enumerate_system_processes\(" process_panel/` → zero matches; GUI still uses `list_processes_detailed` (P2). **Row remains not fully OK/OK/OK.** |
| P63 | Duplicate a process's primary token | NOT-REGISTERED + NO-CONTROL | **FIXED — OK/OK/OK** | L1: `duplicate_token(pid)` process.py:6829 (unchanged, real `DuplicateTokenEx` chain). L2: new `ToolFunction(name="process.duplicate_token", ...)` process.py:1086-1092, one required `pid:integer` — matches. No capability gate. L3: `system_tab.py:182-186` adds "Duplicate Token" button wired to `_on_duplicate_token` (system_tab.py:649-673), calls `self._bridge.duplicate_token(pid)` via `run_bridge_coroutine_logged`, renders the resulting handle into `_token_status`. |
| P64 | Remove a privilege from a token | NOT-REGISTERED + NO-CONTROL | **FIXED — OK/OK/OK** | L1: `remove_privilege(pid, privilege_name)` process.py:6931 (unchanged, real). L2: new `ToolFunction(name="process.remove_privilege", ...)` process.py:1093-1100, two required params `pid:integer`, `privilege_name:string` — matches. No capability gate. L3: `system_tab.py:188-201` adds a privilege-name `QLineEdit` + "Remove Privilege" button wired to `_on_remove_privilege` (system_tab.py:675-712), confirms via `QMessageBox`, calls `self._bridge.remove_privilege(pid, privilege_name)`. |
| P65 | Time a thread wait | NOT-REGISTERED + NO-CONTROL | **FIXED — OK/OK/OK** | L1: `time_thread_wait(tid, timeout_ms=0)` process.py:6758 (unchanged, real). L2: new `ToolFunction(name="process.time_thread_wait", ...)` process.py:1101-1108, `tid:integer required`, `timeout_ms:integer optional default 0` — matches. No capability gate. L3: `threads_tab.py:167-172` adds "Time Wait" button wired to `_on_time_thread_wait` (threads_tab.py:491-521), resolves the selected TID and calls `self._bridge.time_thread_wait(tid)`, renders result/elapsed_us into `_wait_status`. |
| P66 | Detect kernel debugger | NOT-REGISTERED + NO-CONTROL | **FIXED — OK/OK/OK** | L1: `detect_kernel_debugger(pid)` process.py:7170 (unchanged, real `NtQueryInformationProcess(ProcessDebugPort)`). L2: new `ToolFunction(name="process.detect_kernel_debugger", ...)` process.py:1109-1115, one required `pid:integer` — matches. No capability gate. L3: `system_tab.py:412-421` adds "Detect Kernel Debugger" button wired to `_on_detect_kernel_debugger` (system_tab.py:1083-1107), calls `self._bridge.detect_kernel_debugger(pid)`, renders result into `_kernel_dbg_status`. |

PROCESS: **8 of 21 fixed to OK/OK/OK** (P13, P42, P43, P63, P64, P65, P66,
plus P20 unchanged-already-registered-but-still-gapped counted separately
below). **7 of 21 upgraded from NOT-REGISTERED to registered-but-still
NO-CONTROL** (P25, P26, P29, P38, P39, P55, P62 — L1/L2 now genuinely
complete and schema-correct, but zero GUI wiring exists, so these rows are
**not** fully OK/OK/OK). **6 of 21 completely untouched**
(P20, P47, P48, P49, P56, P57, P58 — 7 actually, see full list in
`still_broken` below): device I/O (P47-P49), section objects (P56-P58), and
P20 all remain exactly as the original audit found them — no L1, L2, or L3
change of any kind.

---

## Schema / dispatch spot-checks (beyond line-citation matching)

For every newly-registered `ToolFunction` in both files, the parameter
`name`, `type`, and `required`/`default` were cross-checked word-for-word
against the real method's Python signature (not just presence). All 14 new
registrations (2 sandbox + 12 process) matched exactly — no name mismatch,
no type mismatch, no missing/extra required parameter. This was the
specific bug class the plan called out for `x64dbg.disassemble`/
`frida.attach`; none of that class of defect exists among the sandbox/
process additions.

`core/tools.py:679` capability-gate resolution
(`TOOL_CAPABILITY_MAP.get(function_name) or TOOL_CAPABILITY_MAP.get(attr_name)`)
was checked against every one of the 14 new tool-def names (both the full
`"sandbox.X"`/`"process.X"` form and the bare attr form). Only
`"sandbox.stop"` had any entry in the map at all (both a full-name entry
and a colliding bare-name entry), and the full-name entry — which resolves
first — points to `"dynamic_analysis"`, a capability `SandboxBridge`
genuinely advertises. Confirmed empirically via direct instantiation
(`SandboxBridge().capabilities.has_capability("dynamic_analysis")` → `True`)
and via the existing regression test dispatching through
`ToolRegistry.execute_tool_call`. No other new registration is
capability-gate-blocked (none of the other 13 appear in
`TOOL_CAPABILITY_MAP` under any key).

---

## Tally

Denominator: 9 SANDBOX non-OK rows (S2, S9, S12, S14, S16, S19, S21, S28,
S29) + 21 PROCESS non-OK rows (P13, P20, P25, P26, P29, P38, P39, P42, P43,
P47, P48, P49, P55, P56, P57, P58, P62, P63, P64, P65, P66) = **30 rows
re-checked**.

- **10 now genuinely OK/OK/OK**: S2, S14, S19 (3 sandbox) + P13, P42, P43,
  P63, P64, P65, P66 (7 process).
- **7 upgraded from NOT-REGISTERED to L1/L2-complete but still L3-absent**
  (P25, P26, P29, P38, P39, P55, P62) — real progress (AI/orchestrator can
  now reach these; humans still cannot via the GUI), but not a closed row
  under the plan's OK/OK/OK bar.
- **13 rows completely untouched from the original audit**: S9, S12, S16,
  S21, S28, S29 (6 sandbox NO-CONTROL) + P20, P47, P48, P49, P56, P57, P58
  (7 process) remain exactly as originally found — no L1, L2, or L3 change
  of any kind.

10 + 7 + 13 = 30. **Net result: 10 of 30 non-OK rows are now fully
OK/OK/OK. 7 rows moved from NOT-REGISTERED to L2-complete/L3-absent (real
but partial progress). 13 rows are entirely unchanged from the original
audit.**

No row was found to have been faked, mis-wired, or parameter-mismatched
among the ones the remediation agents did touch — every edit found was a
genuine, correctly-scoped implementation. The gap is one of coverage, not
of quality: the L3 GUI wave for PROCESS device I/O, section objects, and
several of the newly-registered orphan methods (P25, P26, P29, P38, P39,
P55, P62), plus the SANDBOX forensic/analysis NO-CONTROL set (S9, S12, S16,
S21, S28, S29), was never executed.
