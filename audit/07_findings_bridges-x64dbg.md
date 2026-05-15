> # Workgroup Directive — Execution Order 07/23: `bridges-x64dbg`
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
# Findings: bridges-x64dbg

## Files audited (1)

- src/intellicrack/bridges/x64dbg.py

## Findings

### Category 2 - Hardcoded Return Values & Fake Success

#### F-0001 - Many command wrappers return hardcoded `{"success": True, ...}` immediately after enqueuing a fire-and-forget x64dbg script command without inspecting the actual outcome [fixed: audit7/f0001-x64dbg-wrappers]

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 3687-3754, 3756-3768, 3805-3817, 3854-3898, 3900-3913, 4242-4273, 4275-4290, 4292-4304, 4306-4318, 4526-4537, 4539-4590, 4750-4766, 4768-4798, 4800-4815, 4817-4849, 4876-4889, 4891-4913, 5047-5117, 5259-5270, 5403-5414
- **Pattern:** Cat 2, "always return True / fixed success dict regardless of outcome"
- **Excerpt:**

  ```python
  async def run_to(self, address: int) -> dict[str, Any]:
      _logger.debug("run_to_executing", address=hex(address))
      await self._send_pipe_command("exec", {"command": f"runto {hex(address)}"})
      return {"success": True, "target": hex(address)}

  async def patch_instruction(self, address: int, instruction: str) -> dict[str, Any]:
      await self._send_pipe_command("assemble", {"address": hex(address), "instruction": instruction})
      return {"success": True, "address": hex(address), "instruction": instruction}

  async def nop_range(self, address: int, size: int) -> dict[str, Any]:
      await self._send_command(f"fill {hex(address)}, {size}, 90")
      return {"success": True, "address": hex(address), "size": size}
  ```

- **Why this is non-functional:** `_send_pipe_command` only raises when the response includes `success=False`. Every `exec`-routed wrapper forwards a textual x64dbg console command (`runto`, `erun`, `lblset`, `cmtset`, `bp/be/bd`, `bpx`, `fill`, `scriptrun`, `AnimateInto`, `setthreadname`, `bpcond`, `SetBreakpointLog`, `LibrarianSetBreakPoint`, `TraceIntoConditional`, etc.). x64dbg's interpreter dispatches asynchronously and reports success only that the command parsed - e.g. `bpx kernel32.NoSuchSymbol` parses fine but never sets a real breakpoint, `runto` returns immediately without waiting for the address, `setthreadname` silently fails for invalid TIDs. Wrappers synthesise `{"success": True, ...}` regardless of debugger state. `patch_instruction` returns success without verifying the assembled bytes were written.
- **Callers / blast radius:** Every wrapper above is exposed as an LLM `ToolFunction` (lines 1132-1779). UI consumers dispatch via `getattr(bridge, ...)` from `src/intellicrack/ui/panels/x64dbg_panel.py`.
- **Suggested remediation summary:** Verify post-condition (e.g. `bp_list` after `bp`, `reg_get rip` after `runto`, read-back of memory after `fill`/`patch_instruction`) and reflect actual outcome.

#### F-0002 - `set_breakpoint` always returns a synthetic local id and inserts into the local registry even when the plugin call did not actually create a breakpoint

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 2353-2391
- **Pattern:** Cat 2, "synthetic id returned from local counter, no verification target was actually applied"
- **Excerpt:**

  ```python
  await self._send_pipe_command("bp_set", {"address": address, "type": bp_type, "condition": condition})
  bp_id = self._next_bp_id
  self._next_bp_id += 1
  self._breakpoints[address] = BreakpointInfo(...)
  return bp_id
  ```

- **Why this is non-functional:** The id returned is a local Python counter with no relationship to any id known to x64dbg. `remove_breakpoint` ignores the id and removes by address (line 2402-2408); `get_breakpoints` (lines 2410-2457) re-mints local ids for plugin-discovered bps. The local registry is updated unconditionally even though the plugin response could be ambiguous. Consumers using the returned id to correlate hit events will fail.
- **Callers / blast radius:** Tool definition at line 856 exposes `x64dbg.set_breakpoint` to LLMs returning `Breakpoint ID`.
- **Suggested remediation summary:** Have plugin return native id; tie removal to native id; fail loudly when plugin returns ambiguous success.

#### F-0003 - `patch_anti_debug` claims success based on `peb["address"]` but `read_peb`'s tool definition does not advertise such a key, and only patches two of the dozens of advertised "common anti-debug checks"

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 5288-5349
- **Pattern:** Cat 2, "success determined by a value the call may not actually have produced"
- **Excerpt:**

  ```python
  peb_addr_raw = peb.get("address")
  if not isinstance(peb_addr_raw, str) or not peb_addr_raw:
      for name in all_checks:
          errors[name] = "cannot read PEB address"
      return {"success": False, "status": status, "errors": errors}
  ```

- **Why this is non-functional:** `read_peb` (lines 4613-4632) returns whatever `peb_read` produces; tool definition at line 1457 documents `beingDebugged`, `imageBaseAddress`, `ntGlobalFlag` - no `address`. If the plugin omits `address`, every call to `patch_anti_debug` fails with "cannot read PEB address". Even when `address` is supplied, only two PEB fields are nuked (BeingDebugged, NtGlobalFlag); dozens of common checks (heap flags, ProcessDebugFlags, ProcessDebugObjectHandle, KdDebuggerNotPresent, hardware breakpoints, IsDebuggerPresent IAT hook, NtQueryInformationProcess) are ignored.
- **Callers / blast radius:** `x64dbg.patch_anti_debug` LLM tool (line 1705).
- **Suggested remediation summary:** Plumb the PEB base address through the RPC; expand the patch set or rename/document the limited scope.

### Category 3 - Simulated / Mocked Functionality

#### F-0004 - Step-execution functions sleep for 50 ms after issuing a step then read registers; the debugger may not have completed the step in 50 ms

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 2317-2351
- **Pattern:** Cat 3, "fixed sleep substitutes for synchronisation primitive / wait-for-event"
- **Excerpt:**

  ```python
  async def step_into(self) -> int:
      _logger.debug("step_into_executing")
      await self._send_pipe_command("step_into")
      await asyncio.sleep(0.05)
      regs = await self.get_registers()
      return regs.rip if self._is_64bit else regs.rip & DWORD_MASK
  ```

- **Why this is non-functional:** `asyncio.sleep(0.05)` is a hard-coded best-effort hack rather than waiting on the x64dbg "stepped"/paused event. 50 ms is far too short for stepping into a syscall, blocking call, or under back-pressure. Subsequent `get_registers` may read the *previous* IP because the step has not finished, or read IP after a hit on a downstream breakpoint. Same pattern in `step_over` and `step_out`.
- **Callers / blast radius:** LLM tools `x64dbg.step_into`/`step_over`/`step_out` (lines 812-829).
- **Suggested remediation summary:** Replace sleep with awaitable resolved by the `step`/`paused` event from `_handle_event`, with bounded timeout that raises `ToolError`.

### Category 4 - Ineffective / Naive Implementations

#### F-0005 - `find_pattern` with wildcards reads only the first `MAX_MEMORY_READ_SIZE` (1 MiB) of every region and silently misses every match outside that window

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 3626-3685
- **Pattern:** Cat 4, "naive single-shot read instead of streaming"
- **Excerpt:**

  ```python
  for region in regions:
      if "r" not in region.protection:
          continue
      try:
          data = await self.read_memory(region.base_address, min(region.size, MAX_MEMORY_READ_SIZE))
      except ToolError as exc:
          continue
      for i in range(len(data) - pat_len + 1):
          matched = not any(pat_bytes[j] is not None and data[i + j] != pat_bytes[j] for j in range(pat_len))
  ```

- **Why this is non-functional:** Heap, image, and mapped sections frequently exceed 1 MiB. Wildcard matching is silently truncated to 1 MiB per region, while the no-wildcard branch goes through `scan_memory` which *does* chunk with overlap. Callers get a different correctness model depending on whether they used a wildcard.
- **Callers / blast radius:** `x64dbg.find_pattern` LLM tool (line 960).
- **Suggested remediation summary:** Use streaming with per-byte mask; or compile to a fast wildcard matcher.

#### F-0006 - `get_threads` returns `start_address=0`, `current_pc=0`, `state="unknown"` for every thread despite the tool advertising "IDs, entry points, and states"

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 3383-3457; advertised at 1116-1119
- **Pattern:** Cat 4, "returns placeholder/sentinel data for advertised fields"
- **Excerpt:**

  ```python
  if te32.th32OwnerProcessID == self._attached_pid:
      threads.append(
          ThreadInfo(
              tid=te32.th32ThreadID,
              start_address=0,
              current_pc=0,
              state="unknown",
          ),
      )
  ```

- **Why this is non-functional:** `THREADENTRY32` from Toolhelp does not expose start address, PC, or state; obtaining them requires `NtQueryInformationThread`/`OpenThread`+`GetThreadContext`. Tool definition advertises "IDs, entry points, and states" but only IDs are returned. LLM workflows relying on `start_address`/`current_pc` will see 0.
- **Callers / blast radius:** `x64dbg.get_threads` LLM tool; UI panels (`process_panel/_threads_tab.py`).
- **Suggested remediation summary:** Open each thread with `THREAD_QUERY_LIMITED_INFORMATION` and call `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`, `GetThreadContext` for PC.

#### F-0007 - `_read_module_entry_point` returns 0 silently for any module whose header read fails, and reads only 256 bytes without validating PE32 vs PE32+ optional header layout

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 3542-3588
- **Pattern:** Cat 4, "silent fallback to 0 sentinel hides errors"
- **Excerpt:**

  ```python
  try:
      _, pe_header = await self._read_pe_header(base_address, module_name, size=256)
  except ToolError as exc:
      _logger.debug("module_entry_point_read_failed", ...)
      return 0
  entry_offset = NT_HEADERS_OPTIONAL_OFFSET + PE_ENTRY_POINT_OFFSET
  ```

- **Why this is non-functional:** Any failure (paged-out header, partial read, ASLR-hidden module, mapped data file) drops `entry_point` to 0 silently. Worse, the entry-point RVA offset is constant (no PE32 vs PE32+ disambiguation) and the read may be too small if `SizeOfOptionalHeader` is non-default.
- **Callers / blast radius:** `get_modules`, `get_entry_point`.
- **Suggested remediation summary:** Read at least `PE_OPTIONAL_HEADER_OFFSET + 0x100`, validate `SizeOfOptionalHeader`, branch on optional header magic.

### Category 5 - Error Handling Anti-Patterns

#### F-0008 - `_is_recoverable_pipe_error` matches by substring on the error string ("pipe", "not connected", "bridge plugin", "not found", "unknown command", "disconnected", "timed out") - any plugin error containing one of these words is silently swallowed

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 2102-2126
- **Pattern:** Cat 5, "string-matching on error message to drive control flow"
- **Excerpt:**

  ```python
  text = str(exc).lower()
  markers = ("pipe", "not connected", "bridge plugin", "not found",
             "unknown command", "disconnected", "timed out")
  return any(marker in text for marker in markers)
  ```

- **Why this is non-functional:** Marker matching catches genuine semantic errors. `"module 'bogus.dll' not found"`, `"address not found in symbol table"`, `"command timed out at 0xDEADBEEF reading guarded page"` are all classified as recoverable, falling back to a less-correct script path that may itself silently succeed. Used in ~20 RPC paths (`disasm`, `bp_list`, `wp_list`, `db_save`/`load`/`clear`, `patch_list`/`restore`, `seh_chain`, `peb_read`, `teb_read`, `pe_directories`, `watch_*`, `trace_record`, `plugin_list`, `scylla_reconstruct`, etc.).
- **Callers / blast radius:** ~20 callers across the bridge.
- **Suggested remediation summary:** Plumb a structured error type/code from the plugin RPC; test programmatically rather than by substring.

#### F-0009 - Bare `except Exception` swallow paths convert any error to `ToolError` then proceed, hiding root cause

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 3081-3083, 3449-3452, 3532-3535, 5758-5762
- **Pattern:** Cat 5, "broad except converts to generic error"
- **Excerpt:**

  ```python
  except Exception:
      _logger.exception("disassembly_failed", address=hex(address), count=count)
      return []
  ```

  ```python
  except Exception as e:
      _logger.warning("x64dbg_get_threads_failed", pid=self._attached_pid, error=str(e))
      msg = f"{_ERR_GET_THREADS_FAILED}: {e}"
      raise ToolError(msg, tool_name="x64dbg") from e
  ```

- **Why this is non-functional:** `disassemble_at` returning `[]` on any unhandled exception means callers cannot tell a region with no instructions from a transient ctypes failure. Bare `Exception` in `_get_threads`/`_get_modules`/`_get_parent_pid` masks programmer errors.
- **Callers / blast radius:** LLM disasm/threads/modules/process tools.
- **Suggested remediation summary:** Narrow except to OSError/struct.error/ToolError; keep Exception only as last resort and re-raise after logging.

### Category 6 - Resource & Lifecycle Issues

#### F-0010 - `read_memory` / `write_memory` / `allocate_memory` / `free_memory` open a fresh process handle on every call, never caching for the lifetime of the attachment

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 2679-2893, 2955-3023
- **Pattern:** Cat 6, "expensive resource acquired/released per call"
- **Excerpt:**

  ```python
  handle = kernel32.OpenProcess(WIN_PROCESS_VM_READ, WIN_NO_INHERIT_HANDLE, self._attached_pid)
  if not handle:
      msg = f"Failed to open process {self._attached_pid}"
      raise ToolError(msg)
  try:
      buffer = ctypes.create_string_buffer(size)
      ...
  finally:
      kernel32.CloseHandle(handle)
  ```

- **Why this is non-functional:** Memory scanning that issues many `read_memory` calls (`scan_memory`, `find_pattern`, `_build_export_entries`, `analyze_entropy`, `yara_scan`, `_read_module_entry_point` x N modules) thrashes process-handle creation. Each `OpenProcess` is also an audit-logged event in some environments.
- **Callers / blast radius:** Every memory read/scan/write tool.
- **Suggested remediation summary:** Cache one handle per access mask in the bridge instance, acquired on `attach`, released on `detach`/`shutdown`, guarded by a lock.

#### F-0011 - `shutdown` does not wrap `_close_connection` in try/except; if it raises, x64dbg.exe is leaked

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 1835-1861, 1996-2001
- **Pattern:** Cat 6, "cleanup not robust to partial failure"
- **Excerpt:**

  ```python
  async def shutdown(self) -> None:
      await self._close_connection()
      if self._process is not None:
          ...
          self._process.terminate()
  ```

- **Why this is non-functional:** If `_close_connection`/`pipe_client.close()` raises, `shutdown` never reaches the process termination block. `_attached_pid`, `_breakpoints`, `_watchpoints` clearing only happens after process is reaped, not in `try/finally`.
- **Callers / blast radius:** `ProcessManager` cleanup, atexit, GUI close handlers.
- **Suggested remediation summary:** Wrap each cleanup step in `try/except Exception`; always reach process termination + clear state in `finally`.

### Category 7 - Concurrency / Async Issues

#### F-0012 - Local `_breakpoints` / `_watchpoints` dicts and counter values are mutated from coroutines and from synchronous `_handle_event` callbacks (called from the named-pipe read thread) without any lock

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 2031-2055, 2353-2391, 2410-2457, 2459-2521, 2523-2564
- **Pattern:** Cat 7, "shared state mutated from multiple threads without synchronisation"
- **Excerpt:**

  ```python
  def _handle_event(self, message: dict[str, Any]) -> None:
      event_type = str(message.get("event", ""))
      if event_type == "breakpoint":
          addr = int(message.get("address", 0))
          bp = self._breakpoints.get(addr)
          if bp is not None:
              bp.hit_count += 1
      elif event_type == "watchpoint":
          for wp in self._watchpoints.values():
              if wp.address == addr:
                  wp.hit_count += 1
                  break
  ```

- **Why this is non-functional:** `_handle_event` is invoked from the named-pipe client's read thread, while the same dicts are mutated/read from the asyncio loop. Iterating `self._watchpoints.values()` while another coroutine deletes an entry will raise `RuntimeError: dictionary changed size during iteration`. `hit_count += 1` races with rebuilds of `BreakpointInfo` in `enable_breakpoint`/`disable_breakpoint`.
- **Callers / blast radius:** Any consumer using event callbacks plus parallel breakpoint manipulation.
- **Suggested remediation summary:** Marshal events back to the asyncio loop with `loop.call_soon_threadsafe` or use a `threading.Lock`.

### Category 9 - Bridge / Tool Integration Failures

#### F-0013 - Most public methods (`run`, `pause`, `stop`, step_*, `set_breakpoint`, `remove_breakpoint`, `set_watchpoint`, `remove_watchpoint`, `get_registers`, `set_register`, `read_peb`, `evaluate_expression`, `get_status`, etc.) unconditionally call `_send_pipe_command` and raise immediately when the C++ plugin is not deployed, despite x64dbg having native script equivalents

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 2056-2100, 2298-2316
- **Pattern:** Cat 9, "bridge advertises feature but transport is unconditionally absent without plugin"
- **Excerpt:**

  ```python
  async def _send_pipe_command(self, command, params=None):
      if not self._plugin_deployed:
          diag = str(self.plugin_status.get("diagnostic", ""))
          msg = f"x64dbg bridge plugin not available: {diag}"
          raise ToolError(msg)
  ```

  ```python
  async def run(self) -> None:
      await self._send_pipe_command("run")
  ```

- **Why this is non-functional:** A fresh install without the C++ plugin built has a debugger UI that cannot run/pause/step despite the GUI claiming the bridge is connected (`self._state.connected = True` after `_start_debugger`). x64dbg has built-in script commands for every one of these (`run`, `pause`, `StopDebug`, `StepInto`, `StepOver`, `StepOut`, `bp`, `bc`, `bphws`, `bpm`, `r`) reachable by `_send_command`. Only some methods (`save_database`, `restore_patch`, `add_watch`, `reconstruct_imports`, `plugin_list`, `disassemble_at`) implement the script fallback.
- **Callers / blast radius:** Every LLM tool, every UI panel button.
- **Suggested remediation summary:** Either make the C++ plugin a hard prerequisite (refuse to start otherwise) or implement script-command fallbacks for every public method.

#### F-0014 - `evaluate_expression` returns `0` for any non-string/non-int payload instead of raising - a real failure to evaluate is indistinguishable from an expression equal to 0

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 4389-4404
- **Pattern:** Cat 9, "ambiguous return value conflates failure with valid result"
- **Excerpt:**

  ```python
  result = await self._send_pipe_command("eval", {"expression": expression})
  if isinstance(result, str):
      return int(result, 0)
  if isinstance(result, int):
      return result
  return 0
  ```

- **Why this is non-functional:** `evaluate_expression("0")` and `evaluate_expression("@<unparseable>")` both return 0. LLM tools using this for offset arithmetic could write to address 0 / set bad breakpoints.
- **Callers / blast radius:** `x64dbg.evaluate_expression` LLM tool.
- **Suggested remediation summary:** Raise `ToolError` when result is neither string nor int; or return `int | None`.

### Category 10 - Subprocess / External Process Issues

#### F-0015 - `_start_debugger` spawns x64dbg with `stdout=PIPE, stderr=PIPE` but never reads the pipes - if x64dbg writes more than the pipe buffer (~64 KiB), it blocks on write and deadlocks

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 1908-1932
- **Pattern:** Cat 10, "subprocess pipe buffer not drained"
- **Excerpt:**

  ```python
  self._process = await asyncio.to_thread(
      Popen,
      [str(exe_path)],
      stdout=PIPE,
      stderr=PIPE,
      startupinfo=si,
  )
  ```

- **Why this is non-functional:** x64dbg.exe is a GUI process; it normally does not write to stdout, but plugins, third-party diagnostics, or `_putts` from native C++ assertions can fill the inherited pipes. Once full, the next write blocks.
- **Callers / blast radius:** Every load/attach call.
- **Suggested remediation summary:** Use `stdout=subprocess.DEVNULL`, `stderr=subprocess.DEVNULL` or spawn a draining thread.

### Category 13 - Logging / Observability Theater

#### F-0016 - INFO-level logs (`breakpoint_set`, `nop_range_filling`, `patches_exporting`, `script_loading`, `plugin_loading`, `handle_closing`, `thread_suspending`, `api_breakpoint_setting`, etc.) emit success messages even though only "command queued" was confirmed

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 2390, 2407, 2498, 2782, 2849, 4302, 4316, 4536, 4548, 4561, 4574, 4588, 4761, 4789, 4810, 4827, 4844, 4886, 4900, 4911, 5057, 5066, 5079, 5089, 5103, 5115, 5268, 5286, 5371
- **Pattern:** Cat 13, "log emits success message regardless of actual result"
- **Excerpt:**

  ```python
  await self._send_pipe_command("bp_set", ...)
  bp_id = self._next_bp_id
  ...
  _logger.info("breakpoint_set", type=bp_type, address=hex(address), id=bp_id)
  return bp_id
  ```

- **Why this is non-functional:** `_send_pipe_command` only throws on `success=False`, so logs only fire on success - but the underlying x64dbg console command returns success-of-parse, not success-of-effect. Operators tailing logs cannot trust that "breakpoint_set" means a breakpoint exists.
- **Callers / blast radius:** Anyone reading the structured log to confirm operation success.
- **Suggested remediation summary:** Either gate INFO logs on a verification step or downgrade to DEBUG with explicit "x64dbg_command_queued" wording.

### Category 15 - Platform / Windows Compatibility

#### F-0017 - `_wait_for_pipe_ready` falls back to `await asyncio.sleep(1.0)` on non-Windows and then claims the pipe is ready

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 1937-1966
- **Pattern:** Cat 15, "non-Windows path is a sleep instead of platform refusal"
- **Excerpt:**

  ```python
  async def _wait_for_pipe_ready(self) -> None:
      if not _IS_WIN32:
          await asyncio.sleep(1.0)
          return
  ```

- **Why this is non-functional:** x64dbg is Windows-only; named pipes at `\\.\pipe\...` do not exist on Linux/Mac. Pretending the pipe is ready masks the Windows-only constraint with a generic 1-second hang followed by a misleading downstream `pipe_client.connect()` failure.
- **Callers / blast radius:** Any non-Windows test of the bridge.
- **Suggested remediation summary:** Raise `ToolError(f"x64dbg {_ERR_REQUIRES_WINDOWS}")` instead of sleeping.

#### F-0018 - `_detect_process_arch` silently defaults to "64-bit" on every error path, including when `OpenProcess` succeeds but `IsWow64Process` fails

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 2258-2284
- **Pattern:** Cat 15, "silently default to most common case on platform error"
- **Excerpt:**

  ```python
  if not _IS_WIN32:
      return True
  try:
      kernel32 = ctypes.windll.kernel32
      handle = kernel32.OpenProcess(0x0400, False, pid)
      if not handle:
          return True
      try:
          is_wow64 = ctypes.c_int(0)
          ok: int = kernel32.IsWow64Process(handle, ctypes.byref(is_wow64))
          return not bool(is_wow64.value) if ok else True
  ```

- **Why this is non-functional:** When `OpenProcess` fails (insufficient privileges, protected process), the bridge silently launches `x64dbg.exe` instead of `x32dbg.exe`. Attaching x64dbg to a 32-bit target then either fails or attaches the wrong debugger.
- **Callers / blast radius:** `attach()` (line 2244). All operations on a misattached debugger.
- **Suggested remediation summary:** Return `Optional[bool]` and raise `ToolError` from `attach()` when detection fails.

### Category 16 - Binary Analysis-Specific Failures

#### F-0019 - `get_resources` only walks the top-level resource directory entries, never recursing into sub-directories - cannot return resource sizes/RVAs as advertised

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 5472-5506
- **Pattern:** Cat 16, "PE walker stops at first level, advertised data fields are missing"
- **Excerpt:**

  ```python
  rsrc_header = await self.read_memory(base_address + rsrc_rva, min(rsrc_size, 4096))
  num_named = struct.unpack_from("<H", rsrc_header, 12)[0]
  num_id = struct.unpack_from("<H", rsrc_header, 14)[0]
  resources: list[dict[str, Any]] = []
  offset = 16
  for i in range(num_named + num_id):
      type_id = struct.unpack_from("<I", rsrc_header, offset)[0]
      resources.append({"index": i, "type_id": type_id, ...})
      offset += 8
  ```

- **Why this is non-functional:** Tool definition (line 1763) advertises "type, id, size, and rva" but only `{"index", "type_id", "type_name"}` is emitted. PE resources are a tree (Type -> Name/Id -> Language -> DataEntry); walking only the top level yields type identifiers but not the leaf `IMAGE_RESOURCE_DATA_ENTRY` with size/RVA. The 4096-byte cap also under-reads version-rich modules.
- **Callers / blast radius:** `x64dbg.get_resources` LLM tool.
- **Suggested remediation summary:** Implement recursive resource walk; for each leaf parse `OffsetToData` and `Size`.

#### F-0020 - `_build_export_entries` silently truncates the export name list to `PE_EXPORT_MAX` (4096) names with no warning

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 4118-4154
- **Pattern:** Cat 16, "advertised data is silently truncated to a hard cap"
- **Excerpt:**

  ```python
  for i in range(min(num_names, PE_EXPORT_MAX)):
      name_rva = struct.unpack_from("<I", name_ptrs, i * 4)[0]
      ordinal_index = struct.unpack_from("<H", ordinal_table, i * 2)[0]
      func_rva = struct.unpack_from("<I", addr_table, ordinal_index * 4)[0]
      ordinal = ordinal_base + ordinal_index
      func_name, read_error = await self._read_export_name(...)
  ```

- **Why this is non-functional:** Modern Windows libraries (`combase.dll`, `windows.storage.dll`, `xul.dll`) regularly have thousands of exports. No log warning when truncation happens. LLM workflows resolving an export beyond index 4095 will get "not found".
- **Callers / blast radius:** `x64dbg.get_module_exports` LLM tool.
- **Suggested remediation summary:** Remove the cap or surface a `truncated: True` indicator and continue.

#### F-0021 - `analyze_entropy` reads the entire region in one call - exceeds typical pipe/RPM limits and fails entirely if any page in the range is unreadable

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 4915-4947
- **Pattern:** Cat 16, "callers exceed transport limit silently"
- **Excerpt:**

  ```python
  async def analyze_entropy(self, address: int, size: int, block_size: int = 256):
      data = await self.read_memory(address, size)
      results: list[dict[str, Any]] = []
      for offset in range(0, len(data), block_size):
          block = data[offset : offset + block_size]
  ```

- **Why this is non-functional:** `ReadProcessMemory` returns False (and 0 bytes) when *any* page in the range is unreadable; `read_memory` raises and the caller gets nothing instead of partial entropy. There is no chunking and no per-block read on failure.
- **Callers / blast radius:** `x64dbg.analyze_entropy` LLM tool.
- **Suggested remediation summary:** Read in `block_size` chunks individually so a bad block does not abort the whole analysis; surface skipped block counts.

### Category 18 - GUI / UX Wiring Failures

#### F-0022 - `set_breakpoint_on_api` uses `bpx module.function` which fails for forwarders, ordinals, manifest-resolved imports, or APIs not yet imported - failure is invisible due to F-0001

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 3900-3913
- **Pattern:** Cat 18, "exposed action does not robustly handle the input set its UI advertises"
- **Excerpt:**

  ```python
  async def set_breakpoint_on_api(self, module: str, function: str) -> dict[str, Any]:
      target = f"{module}.{function}"
      _logger.info("api_breakpoint_setting", target=target)
      await self._send_pipe_command("exec", {"command": f"bpx {target}"})
      return {"success": True, "target": target}
  ```

- **Why this is non-functional:** `bpx` requires a name x64dbg can resolve at the moment of the call. Forwarders (`kernel32.HeapAlloc -> ntdll.RtlAllocateHeap`), ordinal-only exports, delay-loaded imports - none produce `success=False` because `bpx` parses fine; the breakpoint silently never fires. A GUI button to "break on every CreateFileW" appears to succeed but never breaks.
- **Callers / blast radius:** `x64dbg.set_breakpoint_on_api` LLM tool; UI buttons in `x64dbg_panel.py`.
- **Suggested remediation summary:** Resolve the function via `evaluate_expression(f'GetProcAddress(<module>,"<function>")')`, validate non-zero, then place breakpoint at the resolved VA via `bp_set` and report the resolved address.

### Category 19 - Data Parsing / Format Issues

#### F-0023 - `_detect_architecture` returns `True` (= 64-bit) for any I/O failure, files smaller than `PE_MAGIC_OFFSET`, files lacking `MZ`, files lacking `PE\x00\x00`, and `False` for any non-x86 architecture (ARM/ARM64/IA64) - silently launches the wrong debugger

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 2200-2232
- **Pattern:** Cat 19, "fall-through to default rather than reject"
- **Excerpt:**

  ```python
  machine = int.from_bytes(data[pe_offset + 4 : pe_offset + 6], "little")
  return False if machine == PE32_MACHINE else machine == PE64_MACHINE
  ```

- **Why this is non-functional:** ARM/ARM64/IA64 PE files become "not 64-bit-x86" and return `False`, causing x32dbg.exe to launch, which cannot debug an ARM64 executable. There is no surfacing of "unsupported architecture".
- **Callers / blast radius:** `load()` (line 2168), spawn paths.
- **Suggested remediation summary:** Return tri-state (`x64`, `x32`, `unsupported`) and raise `ToolError` for unsupported.

#### F-0024 - `_extract_command_line_from_peb` silently trims an odd `length` byte before decoding utf-16-le instead of rejecting the malformed input

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 481-513
- **Pattern:** Cat 19, "silently coerce malformed input"
- **Excerpt:**

  ```python
  length = int.from_bytes(ustr_bytes[:2], "little")
  buf_offset = POINTER_SIZE_64 if ptr_size == POINTER_SIZE_64 else POINTER_SIZE_32
  buf_ptr = int.from_bytes(ustr_bytes[buf_offset : buf_offset + ptr_size], "little")
  if length <= 0 or buf_ptr == 0:
      return None
  if length % 2 != 0:
      length -= 1
  ```

- **Why this is non-functional:** `UNICODE_STRING.Length` is always even for a well-formed PEB; observing odd length indicates a corrupt read. Silently dropping the last byte hides this anomaly. `MaximumLength` is not bounds-checked.
- **Callers / blast radius:** `_read_process_command_line` -> `get_process_info`.
- **Suggested remediation summary:** Reject odd length with debug log + `None`; bounds-check against `MaximumLength`.

### Category 20 - Dead Code & Unreachable Paths

#### F-0025 - `WIN_NO_INHERIT_HANDLE: bool = False` is a top-level constant suggesting configurability that does not exist; literal `False` is also used in some `OpenProcess` calls inconsistently

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 167
- **Pattern:** Cat 20, "constant with no real use / suggests configurability that does not exist"
- **Excerpt:**

  ```python
  WIN_NO_INHERIT_HANDLE: bool = False
  ```

- **Why this is non-functional:** No place in the bridge wants `True`. Reading the code suggests an inheritance toggle exists when it does not. The constant is shadowed by per-call literals at lines 273 and 399.
- **Callers / blast radius:** Internal only.
- **Suggested remediation summary:** Inline the literal `False` (or use `wintypes.BOOL(0)`) and delete the constant.

### Category 21 - Documentation / Signature Drift

#### F-0026 - `set_breakpoint`'s tool definition advertises a `condition` parameter; the implementation forwards it via `bp_set` payload but does not also issue a `bpcond` script command, so honouring the condition depends on undocumented plugin behaviour

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 829-856, 2353-2391
- **Pattern:** Cat 21, "advertised parameter not honoured by implementation"
- **Excerpt:**

  ```python
  ToolFunction(
      name="x64dbg.set_breakpoint",
      ...
      ToolParameter(name="condition", type="string", description="Conditional expression", required=False),
  ```

  ```python
  await self._send_pipe_command("bp_set", {"address": address, "type": bp_type, "condition": condition})
  ```

- **Why this is non-functional:** Whether `bp_set` honours `condition` is an undocumented contract with the C++ plugin. If the plugin ignores it, the LLM tool appears to set conditional breakpoints that fire unconditionally.
- **Callers / blast radius:** `x64dbg.set_breakpoint`, `x64dbg.configure_breakpoint`.
- **Suggested remediation summary:** After `bp_set`, always issue `bpcond <addr>, "<condition>"` if condition is not None; verify with `bp_list`.

#### F-0027 - `get_process_info` returns `None` when not attached, but tool definition documents return as "ProcessInfo with threads, modules, command line, and parent PID"

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 1102-1107, 3598-3624
- **Pattern:** Cat 21, "Optional return undocumented"
- **Excerpt:**

  ```python
  async def get_process_info(self) -> ProcessInfo | None:
      if self._attached_pid is None:
          return None
  ```

- **Why this is non-functional:** Returning None from a tool advertised as returning `ProcessInfo` makes the tool LLM-unsafe: the LLM cannot distinguish "no process" from "tool failure".
- **Callers / blast radius:** `x64dbg.get_process_info` LLM tool; orchestrator wrappers.
- **Suggested remediation summary:** Raise `ToolError("not attached")` or add an explicit `attached: bool` field.

### Category 24 - Recovery / Robustness Theater

#### F-0028 - Several methods catch the recoverable-pipe class of `ToolError` and fall back to `_send_command(...)`, but `_send_command` is itself a thin wrapper around `_send_pipe_command("exec", ...)`. The "fallback" travels the same broken pipe

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 4422-4481, 4685-4748, 5119-5139, 5371-5389, 4504-4524
- **Pattern:** Cat 24, "fallback path does not actually solve the failure mode"
- **Excerpt:**

  ```python
  try:
      await self._send_pipe_command("db_save")
  except ToolError as exc:
      if not self._is_recoverable_pipe_error(exc):
          raise
      _logger.debug("db_save_pipe_unavailable_using_script", error=str(exc))
      await self._send_command("dbsave")
  return {"success": True}
  ```

- **Why this is non-functional:** `_send_command` calls `_send_pipe_command("exec", ...)` (lines 2128-2150). When the actual problem is a disconnected pipe, both paths fail; the second failure shadows the first. The "fallback" only helps when the plugin lacks the new RPC name but exposes the legacy script-command interface; in that case the marker substring is `"unknown command"` which works, but in any other failure mode the fallback is theatre.
- **Callers / blast radius:** `save_database`, `load_database`, `clear_database`, `restore_patch`, `add_watch`, `remove_watch`, `plugin_list`, `reconstruct_imports`.
- **Suggested remediation summary:** Distinguish "no such RPC" from "no pipe at all"; only fall back in the former, or implement real reconnection.

#### F-0029 - `get_status` falls back to `{"debugging": False, "paused": False, "initialized": False}` when the plugin returns a non-dict result - all-false state is indistinguishable from a real "not running" state

- **File:** `src/intellicrack/bridges/x64dbg.py`
- **Lines:** 5391-5401
- **Pattern:** Cat 24, "default-false response indistinguishable from real all-false state"
- **Excerpt:**

  ```python
  async def get_status(self) -> dict[str, Any]:
      result = await self._send_pipe_command("status")
      if _is_str_obj_dict(result):
          return dict(result)
      return {"debugging": False, "paused": False, "initialized": False}
  ```

- **Why this is non-functional:** If `_send_pipe_command` returns e.g. a list (RPC contract violation), the bridge silently maps to a false-status. An orchestrator polling status to decide "should I attach?" will repeatedly attach.
- **Callers / blast radius:** `x64dbg.get_status` LLM tool; UI status indicator.
- **Suggested remediation summary:** Raise `ToolError("invalid status response")` instead of returning default-false.
