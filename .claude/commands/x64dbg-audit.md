---
description: Run the x64dbg bridge plugin (C++) audit-and-fix pass via the x64dbg-auditor subagent. Invoke with /x64dbg-audit.
argument-hint: [scope or focus — e.g. "A1 pipe", "cmd_mem_write", or blank for the full sweep]
allowed-tools: Task, Read, Edit, Grep, Glob, Bash
---

You are running the **x64dbg plugin audit** for Intellicrack — a complete production-standards audit-and-fix pass over the C++23 x64dbg/x32dbg bridge plugin (`src/x64dbg-plugin/`). It stands up a Windows named-pipe server that dispatches JSON commands to the x64dbg script API, giving Intellicrack programmatic control of a live debuggee. It runs **inside the x64dbg process**, so a fault crashes the debugger, and the pipe drives full write access to the target — I/O soundness, threading, and access control all matter.

## Execution

1. Launch the `x64dbg-auditor` subagent (via the Task tool) to perform the audit. Its authoritative methodology is [`prompts/x64dbg-Plugin-Audit.md`](../../prompts/x64dbg-Plugin-Audit.md) — instruct it to read that file **in full** and follow it exactly (Ground rules → Part A cross-cutting invariants → Part B per-surface sweep → How to run → Deliverable).
2. **Scope**: pass `$ARGUMENTS` through as the audit focus. If empty, the auditor runs the complete sweep. If a unit, handler, or area is given (e.g. `A1`, `cmd_mem_write`, `pipe_server`), scope the pass to that.
3. When the subagent reports, do **not** accept its claims at face value — move to Accountability.

## Accountability (you own the result)

- **Read the actual diffs** the subagent produced — never approve on its say-so.
- **Re-run the gates yourself** and confirm green: `just clang-format`, `just clang-tidy`, `just cppcheck`, `just cmake-format`, `just cmake-lint`, and a warning-free MSVC `/W4 /permissive-` build (note `/WX-` means warnings do not fail the build — a warning is still a finding). For any Python bridge code touched: `just ruff` / `just basedpyright` / `just pydoclint` / `just pydocstyle` at zero findings.
- **Rebuild-before-test discipline**: a source change is untested until the plugin is rebuilt (CMake `build_x64/` → `bin/`) and deployed to `C:\Tools\x64dbg`. Confirm any behavioral test ran against the **rebuilt** `.dp64`, not a stale one, with revert→RED→restore→rebuild in `try/finally`.
- **Reject** any suppression (`// NOLINT`, `#pragma warning(disable)`) beyond the two pre-existing load-bearing `4324` carve-outs, any weakened gate config, any pipe-protocol break, and any stub/ineffective handler.
- Summarize the confirmed findings and their fixes, **severity-ordered (crash-in-host / I-O-soundness / access-control first)**, each with `file:line`.
