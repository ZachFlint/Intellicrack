# Bridge Completeness Audit — Slice 10: SANDBOX + PROCESS

Audited: `src/intellicrack/bridges/sandbox_bridge.py` (2525 lines),
`src/intellicrack/bridges/process.py` (9261 lines),
`src/intellicrack/ui/panels/sandbox_panel.py` (2013 lines),
`src/intellicrack/ui/panels/process_panel/{base,process_tab,memory_tab,modules_tab,threads_tab,system_tab}.py`.

## Architecture note on "Layer 2"

This codebase does not use a `_td(...)` helper. Tool-call dispatch definitions
are declared as `ToolFunction(name="sandbox.xxx"/"process.xxx", ...)` entries
inside `_get_tool_definition()`/module-level `_PROCESS_FUNCTIONS` lists in
each bridge file, and are dispatched generically by
`ToolRegistry.execute_tool_call()` in `src/intellicrack/core/tools.py:551`
via `getattr(bridge, attr_name)` (tools.py:585-586). A method is
AI/orchestration-reachable iff a `ToolFunction(name=...)` entry exists for
it. Several bridge methods are pure **dispatch shims** (e.g. `process.list`
→ `list_processes`, `process.open` → `open_process`, `sandbox` names already
match method names 1:1) — these are intentional naming-alias layers, not
gaps, and are noted as such below.

---

## SANDBOX coverage matrix

Ground truth: submit/run a sample, configure VM/environment, retrieve
artifacts/reports, network capture, behavior/API-call capture, plus
lifecycle (create/destroy/snapshot/pause-resume) and forensic extraction
typical of Cuckoo/CAPE/Joe Sandbox-class tooling.

| # | Native feature | Bridge method (file:line) | Tool-def | GUI control |
|---|---|---|---|---|
| S1 | Create sandbox instance | OK `create()` sandbox_bridge.py:1014 | OK `sandbox.create` sandbox_bridge.py:395 | OK `_on_create` sandbox_panel.py:517-536 (calls `create(sandbox_type=...)`) |
| S2 | Configure VM: timeout/network/memory limits | OK params exist on `create()` sandbox_bridge.py:1014-1021 | OK `timeout_seconds`/`network_enabled`/`memory_limit_mb` params sandbox_bridge.py:410-430 | **DEAD-CONTROL** — panel only has `sandbox_type_combo` (sandbox_panel.py:126-128); `_on_create` (sandbox_panel.py:527-528) passes only `sandbox_type`, no widgets exist for timeout/network/memory |
| S3 | Destroy instance | OK `destroy()` sandbox_bridge.py:1096 | OK `sandbox.destroy` sandbox_bridge.py:435 | OK `_on_destroy` sandbox_panel.py:580-598, also cleanup path sandbox_panel.py:344 |
| S4 | Run/submit binary sample (args, sandbox_type, time_limit, monitor) | OK `run_binary()` sandbox_bridge.py:1131-1210 real impl (path-exists check, delegates to manager, builds `ExecutionReport`) | OK `sandbox.run_binary` sandbox_bridge.py:448 | OK `_on_run_binary` sandbox_panel.py:702-745 (binary path, args wired; `monitor` defaults True, no UI toggle but functional) |
| S5 | Execute arbitrary command in running sandbox | OK `execute()` sandbox_bridge.py:1212 | OK `sandbox.execute` sandbox_bridge.py:495 | OK `_on_execute_command` sandbox_panel.py:1749-1771 |
| S6 | Copy file into sandbox | OK `copy_to()` sandbox_bridge.py:1279 | OK `sandbox.copy_to` sandbox_bridge.py:527 | OK `_on_copy_in` sandbox_panel.py:1520-1558 |
| S7 | Copy file out of sandbox | OK `copy_from()` sandbox_bridge.py:1329 | OK `sandbox.copy_from` sandbox_bridge.py:552 | OK `_on_copy_out` sandbox_panel.py:1576-1614 |
| S8 | Poll status / list active instances (combined) | OK `status()` sandbox_bridge.py:1376 | OK `sandbox.status` sandbox_bridge.py:577 | OK `_poll_status` sandbox_panel.py:1802-1814, populates `_instances_tree` via `_populate_instances_tree` sandbox_panel.py:1832 |
| S9 | List all sandbox instances (standalone) | OK `list()` sandbox_bridge.py:1386 | OK `sandbox.list` sandbox_bridge.py:583 | **NO-CONTROL** — never called from sandbox_panel.py (instances tree is fed by `status()`, not `list()`); orphan relative to GUI |
| S10 | Create snapshot | OK `snapshot_create()` sandbox_bridge.py:1407 | OK `sandbox.snapshot_create` sandbox_bridge.py:589 | OK `_on_take_snapshot` sandbox_panel.py:1007-1037 |
| S11 | Restore snapshot | OK `snapshot_restore()` sandbox_bridge.py:1452 | OK `sandbox.snapshot_restore` sandbox_bridge.py:608 | OK `_on_restore_snapshot` sandbox_panel.py:1075-1100 |
| S12 | List snapshots | OK `snapshot_list()` sandbox_bridge.py:1497 | OK `sandbox.snapshot_list` sandbox_bridge.py:627 | **NO-CONTROL** — no widget/handler in sandbox_panel.py calls `snapshot_list` (snapshot combo/list, if any, is not backed by this call) |
| S13 | Delete snapshot | OK `snapshot_delete()` sandbox_bridge.py:1543 | OK `sandbox.snapshot_delete` sandbox_bridge.py:640 | OK `_on_delete_snapshot` sandbox_panel.py:1700-1725 |
| S14 | Pause running QEMU VM | OK `stop()` sandbox_bridge.py:1592-1643 real QMP `qmp.stop()` call | **NOT-REGISTERED** — no `sandbox.stop` ToolFunction entry (only `sandbox.cont` sandbox_bridge.py:659 is registered) | OK `_on_pause_vm` sandbox_panel.py:1666-1682 (GUI-reachable but AI/orchestrator cannot invoke this method by name) |
| S15 | Resume paused QEMU VM | OK `cont()` sandbox_bridge.py:1645 | OK `sandbox.cont` sandbox_bridge.py:659 | OK `_on_continue_vm` sandbox_panel.py:1632-1648 |
| S16 | Retrieve pending QEMU guest-agent messages | OK `get_pending_messages()` sandbox_bridge.py:1698 real impl, raises ToolError on dead channel | OK `sandbox.get_pending_messages` sandbox_bridge.py:672 | **NO-CONTROL** — no caller in sandbox_panel.py |
| S17 | Start network capture (PCAP) | OK `pcap_start()` sandbox_bridge.py:1757 | OK `sandbox.pcap_start` sandbox_bridge.py:685 | OK `_on_pcap_toggle`→`pcap_start` sandbox_panel.py:1161-1180 |
| S18 | Stop network capture (explicit capture_id) | OK `pcap_stop()` sandbox_bridge.py:1798 | OK `sandbox.pcap_stop` sandbox_bridge.py:698 | OK `_on_pcap_toggle`→`pcap_stop` sandbox_panel.py:1180-1181 |
| S19 | Stop network capture (teardown/cleanup variant) | OK `stop_pcap()` sandbox_bridge.py:1847-1891 real impl (delegates to `pcap_stop`, tolerant no-op if none active) | **NOT-REGISTERED** — no `sandbox.stop_pcap` ToolFunction; AI cannot invoke directly | OK `_cleanup()` sandbox_panel.py:329-341 calls it on panel teardown |
| S20 | Capture VM screenshot | OK `screenshot()` sandbox_bridge.py:1930 | OK `sandbox.screenshot` sandbox_bridge.py:724 | OK `_on_screenshot` sandbox_panel.py:1123-1139 |
| S21 | Apply anti-evasion hardening profile | OK `anti_evasion()` sandbox_bridge.py:1977-2021 real impl (`instance.sandbox.apply_anti_evasion`) | OK `sandbox.anti_evasion` sandbox_bridge.py:744 | **NO-CONTROL** — no widget/handler in sandbox_panel.py |
| S22 | Full memory dump of guest/target | OK `memory_dump()` sandbox_bridge.py:2023 | OK `sandbox.memory_dump` sandbox_bridge.py:764 | OK `_on_memory_dump` sandbox_panel.py:1242-1258 |
| S23 | Extract dropped files (artifact retrieval) | OK `extract_dropped_files()` sandbox_bridge.py:2093 | OK `sandbox.extract_dropped_files` sandbox_bridge.py:798 | OK `_on_extract_files` sandbox_panel.py:1280-1296 |
| S24 | YARA scan of sample/artifacts | OK `yara_scan()` sandbox_bridge.py:2140 | OK `sandbox.yara_scan` sandbox_bridge.py:818 | OK `_on_yara_scan` sandbox_panel.py:1318-1334 |
| S25 | Extract IOCs from execution report | OK `extract_iocs()` sandbox_bridge.py:2188 | OK `sandbox.extract_iocs` sandbox_bridge.py:845 | OK `_on_extract_iocs` sandbox_panel.py:1365-1381 |
| S26 | Execution timeline (behavior capture, chronological) | OK `timeline()` sandbox_bridge.py:2234 | OK `sandbox.timeline` sandbox_bridge.py:858 | OK `_on_timeline` sandbox_panel.py:1417-1432 |
| S27 | Behavior/signature detection (API-call/behavior capture) | OK `detect_behaviors()` sandbox_bridge.py:2285 | OK `sandbox.detect_behaviors` sandbox_bridge.py:878 | OK `_on_detect_behaviors` sandbox_panel.py:1467-1483 |
| S28 | C2 communication pattern detection | OK `detect_c2()` sandbox_bridge.py:2363-2407 real impl (delegates to `analysis.detect_c2_patterns` on `network_activity`) | OK `sandbox.detect_c2` sandbox_bridge.py:900 | **NO-CONTROL** — no widget/handler in sandbox_panel.py |
| S29 | Diff two execution reports | OK `diff()` sandbox_bridge.py:2409-2468 real impl (delegates to `analysis.diff_reports`) | OK `sandbox.diff` sandbox_bridge.py:913 | **NO-CONTROL** — no widget/handler in sandbox_panel.py |
| S30 | Get embedded VNC display port | OK `get_vnc_port()` sandbox_bridge.py:2470 | OK `sandbox.get_vnc_port` sandbox_bridge.py:932 | OK `_on_vnc_port_received` sandbox_panel.py:1900-1910, feeds embedded VNC widget (line 270) |

### SANDBOX summary
- Fully ported (OK/OK/OK): **21 / 30** (S1, S3-S8, S10, S11, S13, S15, S17, S18, S20, S22-S27, S30)
- DEAD-CONTROL (config gap): 1 (S2)
- NO-CONTROL: 6 (S9, S12, S16, S21, S28, S29)
- NOT-REGISTERED: 2 (S14 `stop`/pause, S19 `stop_pcap`)

---

## PROCESS coverage matrix

Ground truth (Windows process-inspection/manipulation surface): enumerate
processes, attach/open, close, terminate, suspend/resume, read/write memory,
allocate/free/protect/decommit memory regions, memory-map & pattern search,
list modules, inject DLL, list threads + per-thread context/stack/TLS/fiber,
list handles, list windows, list services, token privileges, PEB/TEB
inspection, mitigation policies, environment block, named pipes, COM
servers, .NET/CLR detection, device I/O (DeviceIoControl), job objects, GUI
resource counters, registry access, section objects, architecture
detection, system information queries.

| # | Native feature | Bridge method (file:line) | Tool-def | GUI control |
|---|---|---|---|---|
| P1 | List processes (basic) | OK `list_processes()` process.py:1919-1953 real Toolhelp32 snapshot walk | OK `process.list` process.py:539 (dispatch shim `list()` process.py:1855-1875 → `list_processes`) | Not directly used (superseded by P2 in GUI) |
| P2 | List processes (detailed: arch/mem/threads) | OK `list_processes_detailed()` process.py:2001 | OK `process.list_detailed` process.py:547 (shim `list_detailed()` process.py:1877-1896) | OK `_refresh_process_list`→`list_processes_detailed` process_tab.py:355-356 |
| P3 | Open/attach to process | OK `open_process()` process.py:2347-2395 real `OpenProcess` w/ access-rights map | OK `process.open` process.py:555 (shim `open()` process.py:1897-1917) | OK `_on_attach`→`open_process` process_tab.py:484-485 |
| P4 | Close process handle | OK `close()` process.py:1494 | OK `process.close` process.py:570 | OK `_on_detach`→`close` process_tab.py:508-509 |
| P5 | Terminate process | OK `terminate()` process.py:2397-2436 real `TerminateProcess` | OK `process.terminate` process.py:572 | OK `_on_kill`→`terminate` process_tab.py:590-591 |
| P6 | Suspend process (all threads) | OK `suspend()` process.py:2438 | OK `process.suspend` process.py:580 | OK process_tab.py:528-529 and threads_tab.py:450-451 |
| P7 | Resume process | OK `resume()` process.py:2479 | OK `process.resume` process.py:588 | OK process_tab.py:549-550 and threads_tab.py:470-471 |
| P8 | Read process memory | OK `read_memory()` process.py:2524 | OK `process.read_memory` process.py:596 | OK memory_tab.py:485-486 |
| P9 | Write process memory | OK `write_memory()` process.py:2554 | OK `process.write_memory` process.py:605 | OK memory_tab.py:563-564 |
| P10 | Allocate memory | OK `allocate()` process.py:2587 | OK `process.allocate` process.py:614 | OK memory_tab.py:600-601 |
| P11 | Free memory | OK `free()` process.py:2623 | OK `process.free` process.py:629 | OK memory_tab.py:657-658 |
| P12 | Change memory protection | OK `protect()` process.py:2653 | OK `process.protect` process.py:637 | OK memory_tab.py:709-710 |
| P13 | Decommit memory region | OK `decommit_memory()` process.py:6944-6988 real `VirtualFreeEx(MEM_DECOMMIT)` | **NOT-REGISTERED** — no `process.decommit_memory` ToolFunction | **NO-CONTROL** — no caller anywhere in process_panel/ |
| P14 | Enumerate memory regions/map | OK `get_memory_map()` process.py:2702 | OK `process.get_memory_map` process.py:663 | OK memory_tab.py:449-450 |
| P15 | Search byte/wildcard pattern in memory | OK `search_pattern()` process.py:2766 | OK `process.search_pattern` process.py:677 | OK memory_tab.py:767-768 |
| P16 | List loaded modules | OK `get_modules()` process.py:2980 | OK `process.get_modules` process.py:647 | OK modules_tab.py:332-333 |
| P17 | Inject DLL (CreateRemoteThread+LoadLibraryW) | OK `inject_dll()` process.py:3616-3646 real remote-alloc + `_inject_dll_with_remote_mem` process.py:3648 | OK `process.inject_dll` process.py:697 | OK modules_tab.py:389-390 and process_tab.py:638-639 |
| P18 | List threads | OK `get_threads()` process.py:3076 | OK `process.get_threads` process.py:655 | OK threads_tab.py:413-414 |
| P19 | Get process info (name/path/cmdline/etc.) | OK `get_process_info()` process.py:3745 | OK `process.get_process_info` process.py:705 | OK process_tab.py:678-679 |
| P20 | Get process working-set memory (MB) | OK `get_process_memory_mb()` process.py:2078 | OK `process.get_process_memory_mb` process.py:713 | **NO-CONTROL** — no direct caller (subsumed into P2's aggregate dict but method itself never called standalone by GUI) |
| P21 | Detect process architecture (x86/x64/ARM) | OK `detect_architecture()` process.py:2119 | OK `process.detect_architecture` process.py:719 | OK `_refresh_arch_label`→`detect_architecture` base.py:265-297 |
| P22 | Token privilege enumeration | OK `get_token_privileges()` process.py:3814 | OK `process.get_token_privileges` process.py:725 | OK `_refresh_privilege_label` base.py:299-337, system_tab.py:543-544 |
| P23 | Adjust token privilege (e.g. SeDebugPrivilege) | OK `adjust_token_privilege()` process.py:3970 | OK `process.adjust_token_privilege` process.py:733 | OK system_tab.py:571-572 |
| P24 | Enumerate handles (numeric, type-index only) | OK `get_handles()` process.py:4159-4190 real, type-name resolved via cached `NtQueryObject` | OK `process.get_handles` process.py:743 | OK modules_tab.py:434-435 |
| P25 | Enumerate handles (raw system-wide, no type resolution) | OK `enumerate_handles()` process.py:6329 real distinct impl | **NOT-REGISTERED** | **NO-CONTROL** — redundant with P24/`enum_handles`; never called |
| P26 | Enumerate handles (system-wide, type-resolved, cached) | OK `enum_handles()` process.py:4394-4423 real | **NOT-REGISTERED** | **NO-CONTROL** — functionally duplicates P24 scoped to all PIDs; orphan |
| P27 | Enumerate top-level windows | OK `get_windows()` process.py:4483 | OK `process.get_windows` process.py:751 | OK system_tab.py:612-613 |
| P28 | List services (by owning PID) | OK `list_services()` process.py:4606 | OK `process.list_services` process.py:759 | OK system_tab.py:649-650 |
| P29 | Enumerate services (by active/inactive state) | OK `enumerate_services()` process.py:6558-6588 real, distinct filter axis (state, not PID) | **NOT-REGISTERED** | **NO-CONTROL** |
| P30 | Read PEB (Process Environment Block) | OK `read_peb()` process.py:4772 | OK `process.read_peb` process.py:767 | OK system_tab.py:679-680 |
| P31 | Read TEB (Thread Environment Block) | OK `read_teb()` process.py:5073 | OK `process.read_teb` process.py:775 | OK system_tab.py:710-711 |
| P32 | Enumerate process heaps + blocks | OK `get_heaps()` process.py:5274 | OK `process.get_heaps` process.py:783 | OK modules_tab.py:469-470 |
| P33 | Get thread CPU register context | OK `get_thread_context()` process.py:5346 | OK `process.get_thread_context` process.py:791 | OK threads_tab.py:505-506 |
| P34 | Set thread CPU register context | OK `set_thread_context()` process.py:5513 | OK `process.set_thread_context` process.py:799 | OK threads_tab.py:618-619 |
| P35 | Stack walk (call stack unwind) | OK `stack_walk()` process.py:5682 | OK `process.stack_walk` process.py:808 | OK threads_tab.py:664-665 |
| P36 | SEH exception-handler chain | OK `get_seh_chain()` process.py:6015 | OK `process.get_seh_chain` process.py:816 | OK threads_tab.py:705-706 |
| P37 | Process mitigation policies (DEP/ASLR/CFG, full) | OK `get_mitigation_policies()` process.py:6079 | OK `process.get_mitigation_policies` process.py:824 | OK system_tab.py:840-841 |
| P38 | Process mitigation policies (simplified flat schema) | OK `get_mitigation_policy()` process.py:7130-7197 real, distinct simplified-schema variant + SEHOP mask query | **NOT-REGISTERED** — naming inconsistency: only plural `process.get_mitigation_policies` is registered, no shim for singular alias | **NO-CONTROL** |
| P39 | Extension-point-disable mitigation policy | OK `get_extension_policy()` process.py:7199-7236 real, distinct `ProcessExtensionPointDisablePolicy` query | **NOT-REGISTERED** | **NO-CONTROL** |
| P40 | Read environment variables from PEB | OK `get_environment()` process.py:7287 | OK `process.get_environment` process.py:832 | OK process_tab.py:702-703 |
| P41 | Connect to named pipe | OK `pipe_connect()` process.py:7443 | OK `process.pipe_connect` process.py:840 | OK system_tab.py:746-747 |
| P42 | Read from named pipe | OK `pipe_read()` process.py:7482 | OK `process.pipe_read` process.py:849 | **DEAD-CONTROL** — pipe table UI exists (system_tab.py:720-755) with connect/close only; no send/receive field wired to `pipe_read` |
| P43 | Write to named pipe | OK `pipe_write()` process.py:7509 | OK `process.pipe_write` process.py:858 | **DEAD-CONTROL** — same pipe table; no widget invokes `pipe_write` |
| P44 | Close named pipe | OK `pipe_close()` process.py:7533 | OK `process.pipe_close` process.py:867 | OK system_tab.py:801-802 |
| P45 | Enumerate COM servers in process | OK `enumerate_com_servers()` process.py:7560 | OK `process.enumerate_com_servers` process.py:875 | OK modules_tab.py:502-503 |
| P46 | Detect .NET/CLR presence | OK `detect_dotnet()` process.py:7753 | OK `process.detect_dotnet` process.py:883 | OK modules_tab.py:535-536 |
| P47 | Open device handle (DeviceIoControl target) | OK `device_open()` process.py:8065 | OK `process.device_open` process.py:891 | **NO-CONTROL** — no "Device" widget anywhere in process_panel/ |
| P48 | Send IOCTL to device | OK `device_ioctl()` process.py:8101 | OK `process.device_ioctl` process.py:899 | **NO-CONTROL** |
| P49 | Close device handle | OK `device_close()` process.py:8162 | OK `process.device_close` process.py:910 | **NO-CONTROL** |
| P50 | Query job object info | OK `get_job_info()` process.py:8189 | OK `process.get_job_info` process.py:918 | OK system_tab.py:988-989 |
| P51 | GDI/User handle counters (GUI resources) | OK `get_gui_resources()` process.py:8625 | OK `process.get_gui_resources` process.py:926 | OK system_tab.py:959-960 |
| P52 | Read registry value (key-path form) | OK `reg_read_value()` process.py:8683 | OK `process.reg_read_value` process.py:934 | OK system_tab.py:871-872 |
| P53 | Enumerate registry subkeys | OK `reg_enum_keys()` process.py:8722 | OK `process.reg_enum_keys` process.py:943 | OK system_tab.py:901-902 |
| P54 | Enumerate registry values | OK `reg_enum_values()` process.py:8789 | OK `process.reg_enum_values` process.py:951 | OK system_tab.py:930-931 |
| P55 | Read registry value (hive+key+value form) | OK `read_registry()` process.py:6990 real, distinct explicit-hive-handle variant | **NOT-REGISTERED** | **NO-CONTROL** — redundant with P52 from GUI's perspective; orphan |
| P56 | Create memory-mapped section object | OK `create_section()` process.py:8860 | OK `process.create_section` process.py:959 | **NO-CONTROL** — no "Section" widget anywhere |
| P57 | Map section into process | OK `map_section()` process.py:8950 | OK `process.map_section` process.py:968 | **NO-CONTROL** |
| P58 | Unmap section | OK `unmap_section()` process.py:1514 | OK `process.unmap_section` process.py:977 | **NO-CONTROL** |
| P59 | Read Thread-Local-Storage slot values | OK `get_tls_values()` process.py:9003 | OK `process.get_tls_values` process.py:990 | OK threads_tab.py:777-778 |
| P60 | Read fiber-local data | OK `get_fiber_data()` process.py:9120 | OK `process.get_fiber_data` process.py:999 | OK threads_tab.py:738-739 |
| P61 | Raw `NtQuerySystemInformation` query | OK `query_system_info()` process.py:9142 | OK `process.query_system_info` process.py:1007 | OK system_tab.py:1034-1035 |
| P62 | Enumerate all system processes (dict form) | OK `enumerate_system_processes()` process.py:6261-6290 real, distinct dict-shaped variant of P1 | **NOT-REGISTERED** | **NO-CONTROL** — redundant with P1/P2; orphan |
| P63 | Duplicate a process's primary token | OK `duplicate_token()` process.py:6724-6824 real `DuplicateTokenEx` | **NOT-REGISTERED** | **NO-CONTROL** |
| P64 | Remove a privilege from a token | OK `remove_privilege()` process.py:6826 | **NOT-REGISTERED** | **NO-CONTROL** |
| P65 | Time a thread wait (`WaitForSingleObject` + timing) | OK `time_thread_wait()` process.py:6653-6722 real | **NOT-REGISTERED** | **NO-CONTROL** |
| P66 | Detect kernel debugger attached to process | OK `detect_kernel_debugger()` process.py:7065-7128 real `NtQueryInformationProcess(ProcessDebugPort)` | **NOT-REGISTERED** | **NO-CONTROL** |
| P67 | Feature availability probe | OK `is_available()` process.py:1828 | (infra method, not orchestration-facing; excluded from denominator) | n/a |

### PROCESS summary
- Fully ported (OK/OK/OK): **47 / 67** (P1-P12, P14-P19, P21-P24, P27-P28, P30-P37, P40, P41, P44-P46, P50-P54, P59-P61)
- DEAD-CONTROL: 2 (P42, P43 — pipe read/write)
- NO-CONTROL: 15 (P20, P25, P26, P29, P39, P47, P48, P49, P55-P58, P62-P64, P65-P66 collapse to distinct rows above — see matrix)
- NOT-REGISTERED: 11 (P13, P25, P26, P29, P38, P39, P55, P62, P63, P64, P65, P66) — note some rows are NOT-REGISTERED *and* NO-CONTROL simultaneously; counted once per gap type in totals below.

(P67 `is_available` excluded from the 67-feature denominator as connectivity-probe infra, not a user-facing capability — total user-facing PROCESS features = 66.)

---

## Combined coverage summary

| Layer state | SANDBOX | PROCESS | Combined |
|---|---|---|---|
| Fully ported (OK/OK/OK) | 21 | 47 | **68 / 96** |
| DEAD-CONTROL | 1 | 2 | 3 |
| NO-CONTROL | 6 | 15 | 21 |
| NOT-REGISTERED | 2 | 11 | 13 |
| STUB / MISSING | 0 | 0 | 0 |

Denominator: 30 SANDBOX + 66 PROCESS = 96 native features (S1-S30, P1-P66,
`is_available` excluded as infra). Every bridge method examined is a real,
working implementation — **zero STUB or MISSING findings** in either bridge.
All gaps are wiring/registration gaps (Layer 2 or Layer 3), not missing
Layer-1 functionality. `sandbox_bridge.py` and `process.py` in fact
implement *more* real capability than either the AI tool surface or the GUI
currently exposes (12 orphan-but-real methods: `stop_pcap`,
`decommit_memory`, `enumerate_handles`, `enum_handles`,
`enumerate_services`, `get_mitigation_policy`, `get_extension_policy`,
`read_registry`, `enumerate_system_processes`, `duplicate_token`,
`remove_privilege`, `time_thread_wait`, `detect_kernel_debugger`,
`get_extension_policy` — several are functional duplicates of a registered
sibling and represent genuine dead code from an orchestration standpoint
even though the implementation itself is correct).

68/96 = 70.8% fully ported across all three layers.

---

## Prioritized gap list

1. **Sandbox VM/environment configuration is unreachable from the GUI**
   (S2). The bridge and tool-definition both support `timeout_seconds`,
   `network_enabled`, and `memory_limit_mb` on `sandbox.create`
   (`sandbox_bridge.py:410-430`), but `sandbox_panel.py` only exposes a
   sandbox-type combo box (`sandbox_panel.py:126-128`) and hardcodes
   defaults via `_on_create` (`sandbox_panel.py:517-536`). This is the
   single highest-impact gap in the slice — it silently strips the AI
   orchestrator's most useful sandbox knobs (network isolation toggle,
   memory ceiling, execution timeout) from human operators. Fix: add
   `QSpinBox`/`QCheckBox` widgets to the sandbox_panel.py create toolbar
   and thread the values into `_on_create`'s `self._bridge.create(...)`
   call.

2. **Named-pipe read/write is dead in the GUI** (P42, P43). The system_tab
   pipe table lets a user connect and close a pipe
   (`system_tab.py:720-810`) but never calls `pipe_read`/`pipe_write`
   (`process.py:7482`, `process.py:7509`), so the feature is unusable for
   its actual purpose (IPC inspection). Fix: add send/receive controls to
   `system_tab.py`'s pipe section wired to `self._bridge.pipe_read(...)`
   and `self._bridge.pipe_write(...)`.

3. **VM pause (`sandbox.stop`) and cleanup PCAP-stop
   (`sandbox.stop_pcap`) are not AI/orchestrator-reachable** (S14, S19).
   Both are real, GUI-wired methods but missing `ToolFunction` entries in
   `sandbox_bridge.py`'s `_get_tool_definition()` (~line 386-940), so an
   AI-driven workflow cannot pause a VM or force-stop a capture
   programmatically — only a human clicking the GUI button can. Fix: add
   `ToolFunction(name="sandbox.stop", ...)` and
   `ToolFunction(name="sandbox.stop_pcap", ...)` entries.

4. **Ten real, correct PROCESS methods have no tool-definition and no GUI
   control at all** (P13 `decommit_memory`, P29 `enumerate_services`, P39
   `get_extension_policy`, P55 `read_registry`, P63 `duplicate_token`, P64
   `remove_privilege`, P65 `time_thread_wait`, P66
   `detect_kernel_debugger`, plus device I/O P47-P49 and section objects
   P56-P58). These represent legitimate, distinct capabilities (not
   simply redundant with a sibling) that are fully implemented in
   `process.py` but completely unreachable by either humans or the AI
   orchestrator. Highest-value among these: `detect_kernel_debugger`
   (anti-debug/anti-analysis relevance) and `decommit_memory` (natural
   companion to the already-wired allocate/free/protect trio in
   `memory_tab.py`). Fix: register `ToolFunction` entries in
   `process.py`'s `_PROCESS_FUNCTIONS` list and add corresponding
   controls — decommit fits naturally into `memory_tab.py` next to
   Free/Protect; kernel-debugger detection fits into `system_tab.py`
   alongside the existing mitigation-policy display.

5. **Device I/O (`device_open`/`device_ioctl`/`device_close`) and section
   objects (`create_section`/`map_section`/`unmap_section`) are fully
   implemented and registered as AI tool functions but have zero GUI
   presence** (P47-P49, P56-P58). These are advanced/niche capabilities
   (driver communication, shared-memory sections) appropriate to gate
   behind an "Advanced" tab rather than surface in the main flow, but
   their total absence from `process_panel/` means a human operator has
   no way to use them without going through the AI chat interface. Lower
   priority than items 1-4, but worth a dedicated "Advanced I/O" sub-tab
   in `process_panel/system_tab.py` or a new panel file.

6. **Six sandbox forensic/analysis methods have no GUI control**
   (S9 `list`, S12 `snapshot_list`, S16 `get_pending_messages`, S21
   `anti_evasion`, S28 `detect_c2`, S29 `diff`). `anti_evasion` and
   `detect_c2`/`diff` are meaningful analyst-facing features (evasion
   hardening before running evasive malware; C2 pattern detection and
   before/after report diffing) that exist only via the AI tool-call path
   today. Fix: add a "Diff Reports" action (pick two prior instance IDs),
   a "C2 Detection" button next to the existing Behaviors button
   (`sandbox_panel.py` around line 1467), and an anti-evasion
   profile-selector alongside VM creation.

7. **Duplicate/near-duplicate implementations create maintenance risk**
   (P25/P26 vs P24, P29 vs P28, P38 vs P37, P55 vs P52, P62 vs P1/P2).
   These are not user-facing gaps (the registered sibling covers the same
   ground-truth feature) but are dead code from an orchestration
   standpoint — `enum_handles`/`enumerate_handles` in particular
   duplicate `get_handles` almost line-for-line. Recommend consolidating
   or explicitly registering the more capable variant and removing the
   other during a future cleanup pass, but this is a code-hygiene item,
   not a completeness gap.
