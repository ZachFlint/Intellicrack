---
description: Run the Hexcore (Rust/PyO3) audit-and-fix pass via the hexcore-auditor subagent. Invoke with /hexcore-audit.
argument-hint: [scope or focus — e.g. "A6", "piece_table.rs", or blank for the full sweep]
allowed-tools: Task, Read, Edit, Grep, Glob, Bash
---

You are running the **Hexcore audit** for Intellicrack — a complete production-standards audit-and-fix pass over the `intellicrack-hexcore` Rust/PyO3 crate (`src/intellicrack-hexcore/`), the engine behind the hex editor and the one place in the codebase with `unsafe` code and a lock-discipline invariant that has already caused a production deadlock.

## Execution

1. Launch the `hexcore-auditor` subagent (via the Task tool) to perform the audit. Its authoritative methodology is [`prompts/Hexcore-Audit.md`](../../prompts/Hexcore-Audit.md) — instruct it to read that file **in full** and follow it exactly (Ground rules → Part A cross-cutting invariants → Part B per-module sweep → How to run → Deliverable).
2. **Scope**: pass `$ARGUMENTS` through as the audit focus. If empty, the auditor runs the complete Part A + Part B sweep. If a module, finding-id, or area is given (e.g. `A6`, `piece_table.rs`, `unsafe`), scope the pass to that.
3. When the subagent reports, do **not** accept its claims at face value — move to Accountability.

## Accountability (you own the result)

- **Read the actual diffs** the subagent produced — never approve on its say-so.
- **Re-run the gate battery yourself** and confirm it is green: `just rustfmt`, `just clippy`, `just test-hexcore` (add `just cargo-deny` / `just machete` / `just typos` if source or dependencies changed).
- **Verify every new test is a real falsifiable gate**: revert the fix, confirm it goes RED, restore. Reject any test that stays green on revert.
- **Reject** any suppression (`#[allow(...)]`, `#[expect(...)]`, `type: ignore`, `# noqa`), any weakened or edited gate config, any public-API or `intellicrack_hexcore.pyi` drift, and any placeholder or ineffective implementation.
- Summarize the confirmed findings and their fixes, **severity-ordered (soundness first)**, each with `file:line`.
