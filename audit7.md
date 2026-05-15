> # Audit List 7 (opus-verified actionable subset, 10 findings)
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


# Findings: bridges-hex (from audit1.md)

## Summary

1 opus-confirmed NEEDS-WORK finding from audit1.md / section `bridges-hex`.

## Findings

#### F-0040 - UTF-16 scanner accepts code units like 0x2070 as printable [fixed: audit7/u01-utf16-scanner]

- **Source audit:** audit1.md / `bridges-hex`
- **Reviewer verdict:** UNCLEAR
- **Reviewer assessment:** The line range provided (5050-5071) does not contain UTF-16 scanning code. Lines in that range contain open_process_memory function and VA mapping logic. No UTF-16 scanner found at documented location. The function may have been refactored or removed.

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5050-5071
- **Pattern:** Cat 16


# Findings: providers-meta (from audit2.md)

## Summary

1 opus-confirmed NEEDS-WORK finding from audit2.md / section `providers-meta`.

## Findings

#### F-0021 - `discover_all` records error events but never invalidates the now-known-stale cache entry [fixed: audit7/u02-discover-cache]

- **Source audit:** audit2.md / `providers-meta`
- **Reviewer verdict:** UNCLEAR
- **Reviewer assessment:** Expected exceptions within discover_one are handled with cache invalidation. However, truly unexpected exceptions escaping discover_one (lines 696-698) are logged but don't trigger cache invalidation. This may be acceptable since such exceptions are unplanned failures, but the audit concern of stale-cache-on-error isn't fully addressed for catastrophic failures.

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 437-467
- **Pattern:** Cat 11


# Findings: config-pyproject (from audit4.md)

## Summary

1 opus-confirmed NEEDS-WORK finding from audit4.md / section `config-pyproject`.

## Findings

#### F-0001 - `pyproject.toml` redundantly declares 95+ dev/test/docs/profile packages as runtime `dependencies` [fixed: audit7/u03-runtime-deps]

- **Source audit:** audit4.md / `config-pyproject`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The defect persists. Lines 43-154 list all 95+ development, testing, documentation, and profiling packages in the main `dependencies` array instead of in `optional-dependencies` extras. This causes `pip install intellicrack` to pull pytest, mypy, bandit, sphinx, mkdocs, torch, transformers, and dozens of other non-runtime packages.

- **File:** `pyproject.toml:43-154`
- **Pattern:** Cat 23, Cat 12
- **Why non-factual:** `pip install intellicrack` pulls pytest, mypy, bandit, basedpyright, ruff, sphinx, mkdocs-material, pre-commit, tox, nox, twine, monkeytype, pyannotate, safety, commitizen, bumpversion as runtime requirements. These are development-time tooling packages that have no business in the published distribution's `[project].dependencies` list — they belong in `[dependency-groups]` / `[project.optional-dependencies]` extras (`dev`, `test`, `docs`, `profile`) instead.
- **Suggested remediation summary:** Move every dev/test/docs/profile-only package from `[project].dependencies` into the appropriate `[dependency-groups]` table (`dev`, `test`, `docs`, `profile`) so that `pip install intellicrack` only pulls genuine runtime requirements. Verify against the existing pixi feature/environment layout in `pyproject.toml` to keep tool resolution consistent.


# Findings: sandbox-py (from audit4.md)

## Summary

6 opus-confirmed NEEDS-WORK findings from audit4.md / section `sandbox-py`.

## Findings

#### F-0001 - `SandboxManager.create()` deadlocks on capacity eviction [fixed: audit7/u04-sandbox-deadlock]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The deadlock vulnerability remains unaddressed in current HEAD. Line 287 acquires `self._lock` with `async with self._lock:`, and line 291 calls `await self.destroy(oldest.id)`. The `destroy()` method at line 357 also does `async with self._lock:`, attempting to acquire the same non-reentrant `asyncio.Lock`. This causes indefinite blocking when capacity eviction is triggered. No fix visible in recent commits.

- **File:** `src/intellicrack/sandbox/manager.py`
- **Lines:** 184-192
- **Pattern:** Cat 7
- **Why this is non-functional:** `SandboxManager.create()` acquires `self._lock`. Inside the critical section, when at capacity it calls `await self.destroy(oldest.id)`. `destroy()` also does `async with self._lock:` to take the same lock. `asyncio.Lock` is not reentrant, so the second acquisition blocks indefinitely.

### Category 1 - Empty / Stub Implementations
#### F-0002 - `QEMUSandbox.start()` instantiates `GuestAgentClient` but never calls `connect` [fixed: audit7/u05-qemu-agent-connect]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The fix claimed in commit 1c3bd185 (test suite F-0002) is not actually present in the code. Line 1452 instantiates `GuestAgentClient` but there is no `await self._agent.connect()` call following it. All code paths guarded by `self._agent.is_connected` remain dead. The test at tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py::TestF0002AgentConnectCalled is flawed: it manually calls `fake_agent.connect()` after the test scenario (line 369) rather than verifying that start() itself calls connect().

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1311 + 1949-1994
- **Pattern:** Cat 1
- **Why this is non-functional:** `GuestAgentClient.is_connected` is permanently `False` for the lifetime of the sandbox. Every code path guarded by `self._agent.is_connected` is dead. The "fallback" path in `run_command` writes a script to `<shared>/input/exec_*.cmd` and polls `<shared>/output/result_*.txt`, but nothing in the guest watches the input folder.

### Category 4 - Wrong Field Returned
#### F-0006 - No mechanism to start the guest agent script [fixed: audit7/u06-guest-agent-bootstrap]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** While commit 1c3bd185 claims to fix F-0006 ("agent script startup"), the actual mechanism for launching the guest agent script in the guest remains unclear in the codebase. The agent scripts are written to shared folders but no evidence of actual guest-side execution trigger (e.g., registry runkey, startup batch, or virtualization guest tools integration) is visible. This appears to be a band-aid fix at best: scripts are created but not executed.

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 1608-1947
- **Pattern:** Cat 1, Cat 9
- **Why this is non-functional:** `start_agent.cmd` and `start_agent.sh` are written into the shared folder, but nothing in the QEMU launch ever arranges for the guest to execute them.

### Category 4 - Wrong Implementation
#### F-0007 - extract_dropped_files won't work if agent disconnected, allowlist mismatch otherwise [fixed: audit7/u07-extract-dropped-files]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** Commit 1c3bd185 claims to fix F-0007 but the underlying issue persists. Given that F-0002 (agent.connect() not called) remains unfixed, `self._agent.is_connected` is always False, making the agent path permanently dead. The file extraction logic still depends on the broken connection path. Without F-0002 being fixed, F-0007 cannot be truly functional.

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2710-2717
- **Pattern:** Cat 4, Cat 14

### Category 21 - Wrong PowerShell Construct
#### F-0029 - QEMU `apply_anti_evasion(profile=...)` ignores profile parameter [fixed: audit7/u08-anti-evasion-profile]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The `profile` parameter is accepted and logged in the result dict, but the actual anti-evasion configuration sourced from `self._qemu_config.anti_evasion_profile` (line 2675) at launch time ignores the runtime `profile` parameter. The comment explicitly states "the actual SMBIOS profile is sourced from QEMUConfig.anti_evasion_profile", making the parameter meaningless for controlling runtime behavior.

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2502-2625
- **Pattern:** Cat 21

### Category 13 - Race Condition / Fixed Sleep
#### F-0031 - QEMU `run_binary` 2-second sleep [fixed: audit7/u09-logs-stable]

- **Source audit:** audit4.md / `sandbox-py`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** Hardcoded `await asyncio.sleep(2)` after binary execution. Like F-0030, this is a race condition mitigation using sleep instead of proper waiting for monitoring log stabilization.

- **File:** `src/intellicrack/sandbox/qemu.py`
- **Lines:** 2152-2156
- **Pattern:** Cat 13


# Findings: ui-panels-process (from audit4.md)

## Summary

1 opus-confirmed NEEDS-WORK finding from audit4.md / section `ui-panels-process`.

## Findings

#### F-0012 - `ThreadsTab` thread combos only update on explicit Refresh [fixed: audit7/u10-threads-auto-refresh]

- **Source audit:** audit4.md / `ui-panels-process`
- **Reviewer verdict:** FAIL
- **Reviewer assessment:** The thread combo boxes are only populated when the Refresh button is clicked. New threads created in the target process will not appear until manual refresh. Dynamic thread creation goes unnoticed.

- **File:** `src/intellicrack/ui/panels/process_panel/_threads_tab.py`
- **Lines:** 96-106, 353-384
- **Pattern:** Cat 11


# Findings: bridges-process (from audit2.md)

## Summary

5 opus-confirmed NEEDS-WORK findings from audit2.md / section `bridges-process`.

## Findings

#### F-0008 - `get_seh_chain` WOW64 pointer-size bug [fixed: audit7/u02-bridges-process]

- **Source audit:** audit2.md / `bridges-process`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** ~4963-5010 (`get_seh_chain`)
- **Pattern:** Cat 4
- **Why this is non-functional:** The native-x64 guard correctly raises `ToolError(_ERR_SEH_NOT_APPLICABLE_X64)`. When the target is WOW64 (a 32-bit process on a 64-bit host — the common real-world case), the code falls through and uses `ptr_size = struct.calcsize("P")`. On a 64-bit Python host that returns 8, so the function reads 16-byte SEH records with `<QQ`. WOW64 SEH records are 8 bytes (two 4-byte x86 pointers). Every address and handler returned for a WOW64 target is silently wrong.
- **Resolution:** `get_seh_chain` now caches `_target_is_wow64()` into a local, hard-codes `ptr_size = _PTR_SIZE_32` (4 bytes) when WOW64, and unpacks with `<II`. The host-derived `struct.calcsize("P")` path now applies only to non-WOW64 targets. New constant `_PTR_SIZE_32` is defined alongside `_PTR_SIZE_64`.

#### F-0019 - `get_handles` tool still returns raw `ObjectTypeIndex` integers [fixed: audit7/u02-bridges-process]

- **Source audit:** audit2.md / `bridges-process`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** ~3396 (`get_handles`), ~3584 (`enum_handles`)
- **Pattern:** Cat 4
- **Why this is non-functional:** A new `enum_handles` method properly resolves type indices to human-readable names via `NtQueryObject(ObjectAllTypesInformation)`, but it is **not registered as a tool**. The tool-callable `process.get_handles` still delegates to `_sync_iterate_handles_for_pid` which returns `"type_index"` as a raw integer. LLM/CLI callers receiving "type_index=37" cannot interpret it.
- **Resolution:** `get_handles` now calls `_build_handle_type_map()` on first use (cached afterwards) and `_sync_iterate_handles_for_pid` resolves each entry's `ObjectTypeIndex` to a `type_name` string via the cached map. The raw `type_index` integer is preserved as a sibling field. The tool-def `returns` text now lists `handle_value, type_index, type_name, granted_access, object_address`.

#### F-0035 - `search_pattern` blocks the event loop across regions [fixed: audit7/u02-bridges-process]

- **Source audit:** audit2.md / `bridges-process`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** ~2352-2417 (`search_pattern`, `_scan_region_pattern`)
- **Pattern:** Cat 7
- **Why this is non-functional:** Handle enumeration at 100k+ entries was correctly moved to `asyncio.to_thread`, but `search_pattern` still iterates regions synchronously inside the coroutine and calls `_scan_region_pattern` without yielding between regions. Large processes with many readable regions stall the event loop for multi-second intervals, blocking concurrent tool calls and UI updates.
- **Resolution:** Each `_scan_region_pattern` invocation is now dispatched via `await asyncio.to_thread(...)` with an additional `await asyncio.sleep(0)` after each region to guarantee the event loop has a chance to service other coroutines between regions.

#### F-0037 - `query_system_info` returns raw bytes against a "hex string" tool-def contract [fixed: audit7/u02-bridges-process]

- **Source audit:** audit2.md / `bridges-process`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** ~7652-7700 (`query_system_info`), tool definition ~line 1006
- **Pattern:** Cat 4
- **Why this is non-functional:** The function's return type is `bytes` and it returns `buffer.raw[: return_length.value]` (raw bytes). The tool definition advertises `returns="Hex string of raw output buffer"`. Every other hex-returning method in this bridge was corrected; this one was missed. LLM callers serialising the return value into a JSON tool response will hit a non-serialisable `bytes` payload.
- **Resolution:** `query_system_info` return annotation is now `-> str` and the success path returns `buffer.raw[: return_length.value].hex()`. The `_system_tab.py` UI consumer was updated to handle the new hex-string contract (decoding via `bytes.fromhex` for the hex-dump display).

#### F-0044 - `pipe_connect` / `device_open` never insert into the shutdown tracking dicts [fixed: audit7/u02-bridges-process]

- **Source audit:** audit2.md / `bridges-process`
- **Reviewer verdict:** PARTIAL
- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** ~5967-6003 (`pipe_connect`), ~6555-6588 (`device_open`), ~1443-1446 (`shutdown` cleanup loop)
- **Pattern:** Cat 4
- **Why this is non-functional:** `shutdown` iterates `self._pipe_handles` and `self._device_handles` to close them, but neither `pipe_connect` nor `device_open` populates those dicts after successfully opening a handle. The dicts are always empty at shutdown. Section handle tracking is wired end-to-end correctly, but pipe and device handles leak unless the caller explicitly calls `pipe_close` / `device_close`.
- **Resolution:** After a successful `CreateFileW`, `pipe_connect` now stores `self._pipe_handles[handle] = pipe_name` and `device_open` stores `self._device_handles[handle] = device_path`. The corresponding `pipe_close` / `device_close` methods now `pop` the entry on a successful close so the dicts reflect only currently-open handles. `shutdown` already iterates these dicts so the leaks are fully closed.
