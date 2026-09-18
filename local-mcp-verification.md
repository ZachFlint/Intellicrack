# Local verification brief — third-party MCP server support (Intellicrack)

You own **every test, every quality gate, and all environment-bound
verification** for the MCP client work. A cloud session writes the
implementation on `feat/mcp-client` per `cloud-mcp-implementation.md` and is
explicitly forbidden from writing tests, running gates other than `ruff`, or
claiming anything is verified.

Treat the cloud PR description as a list of **claims**, not facts. The previous
run of this split (PR #409, provider work) shipped 8 real bugs that only showed
up when the gates actually ran locally — including two that crashed the process.

---

## 0. Why this session exists

The cloud VM is Linux. The project is Windows-first. These cannot run there and
therefore nothing about them is known until you run them:

- `pixi` (win-64-only lock), so no project dependency resolution.
- `basedpyright` meaningfully (stubs and deps resolve out of the win-64 env).
- `pytest` at all — the sandbox is a **Windows Server container**
  (`docker/Dockerfile.windows`) whose runner calls `_ensure_windows_engine()`.
- Anything touching the Windows keyring, Win32 job objects, process trees,
  console-window behaviour, or the Qt GUI.

---

## 1. Order of work

1. **Run the three spikes (§2) before reviewing any code.** Two of them can
   invalidate design choices; finding that out after gating is wasted effort.
2. Static gates (§3) on the branch as delivered.
3. Build the test fixtures (§4).
4. Write and falsify the gate matrix (§5, §6).
5. Live end-to-end verification in the real app (§8).
6. Regression proof that bridges are untouched (§7).

---

## 2. Spikes — run these first

**S-1 — CIMD for a desktop app.** The spec prefers Client ID Metadata
Documents, which require an HTTPS-hosted metadata document. Intellicrack has no
hosted origin. Determine, against a real authorization server, which of CIMD /
pre-registered client id / DCR is actually reachable for a desktop client.
The planned policy is CIMD when a metadata URL is configured → pre-registered
`oauth_client_id` → DCR last with a deprecation warning. **Confirm that policy
is implementable before Phase 2 is gated**; if CIMD is unreachable without a
hosted document, record that and make the pre-registered path primary.

**S-2 — Windows stdio launch hygiene.** Determine whether the SDK's
`mcp.client.stdio.create_windows_process` sets `CREATE_NO_WINDOW`. Launch a
real `npx`-based server and watch for a console flash. Confirm `.cmd` shim
resolution works **without** invoking a shell. Related known trap:
`-WindowStyle Hidden` hides a GUI app's *first* window, which is not the same
fix. Record the finding — the sandboxed-launch work in Phase 3 depends on it.

**S-3 — tool list changes mid-session.** Decide and then gate the
reconciliation: stale canonical names dropped from the advertised set, an
in-flight call to a removed tool failing with a named error, and the generation
bump invalidating remembered approvals.

---

## 3. Static gates (authoritative here)

```bash
just lint
```

```bash
just typecheck
```

- `ruff check` — zero findings.
- `basedpyright` — **zero findings**, and **no suppressions anywhere**. Grep the
  diff for `type: ignore`, `pyright: ignore`, `noqa` and reject any hit; the
  cloud brief forbids them, so a hit is a contract violation, not a style nit.
- `pydoclint` + `pydocstyle` — zero findings. Docstring `Returns:` types must
  agree with the annotations.
- The CLI is authoritative over the LSP when they disagree.
- Confirm the cloud session did not edit `[tool.basedpyright]`,
  `pyrightconfig.json`, `pixi.lock`, `requirements.txt`, `workspace.platforms`,
  or anything under `providers/dialects/`, `bridges/json_schema.py`,
  `providers/tool_names.py`.

---

## 4. Test fixtures you build

All fixtures live in `tests/_helpers/` — **not** in top-level `mcps/`, which is
gitignored. Follow the shape of the existing
`tests/_helpers/provider_endpoint_server.py`.

**Use `mcp.server.mcpserver.MCPServer`. `FastMCP` does not exist in mcp 2.x.**

`tests/_helpers/mcp_test_servers.py` — real servers, driven over **real stdio
subprocesses**, never a mocked transport:

- `well_behaved_server` — a handful of tools with real behaviour, including one
  whose `inputSchema` uses `$ref`/`$defs`/`anyOf`, one named `get__weather`, one
  with a 90-character name, one with a dotted name (`admin.tools.list`), and one
  returning text + image + embedded resource.
- `annotated_server` — tools carrying `readOnlyHint` / `destructiveHint`.
- `slow_server` — a tool that blocks long enough to exercise timeout and
  cancellation.
- `crashing_server` — exits mid-session; used for health, stderr capture and
  reconnect.
- `paginating_server` — 300 tools across several `next_cursor` pages, with
  `ttlMs` set.
- `mutating_server` — changes its tool list on demand and emits
  `notifications/tools/list_changed`.
- `hostile_server` — prompt-injection text in descriptions, an oversized result,
  and a tool count intended to blow the context budget.

`tests/_helpers/mcp_http_server.py` — a real Streamable HTTP server plus a real
local OAuth authorization server (PRM at
`/.well-known/oauth-protected-resource`, metadata discovery, PKCE, and a mode
that returns a **mismatched `iss`** for the RFC 9207 gate).

Tests go in `tests/mcp/`, with orchestrator/registry changes gated under
`tests/core/` and dialogs under `tests/ui/`.

---

## 5. Gate matrix

| # | Gate | Must fail when |
| --- | --- | --- |
| T-1 | stdio connect + `list_tools` against a real subprocess | client/transport regresses |
| T-2 | **Windows process-tree teardown** — assert no descendant PIDs survive `stop()` | job-object teardown regresses |
| T-3 | **Protocol-era negotiation** — same server at `mode="2026-07-28"` and at a `HANDSHAKE_PROTOCOL_VERSIONS` era (2025-11-25) | era negotiation breaks |
| T-4 | Namespacing + dispatch round-trip incl. the dotted MCP name | naming/splitting regresses |
| T-5 | Discovery via `tools.search` → `Session.loaded_tools` → persisted and reloaded | a parallel discovery path appears |
| T-6 | Consent gate: **no process spawns** before approval; argv rendered untruncated (use a 500-char argument) | consent bypass or eliding |
| T-7 | Trust gate: `readOnlyHint` ignored for an untrusted server, honoured for a trusted one | annotation trust regresses |
| T-8 | Approval reset when the tool list changes mid-session | a stale approval survives |
| T-9 | **OAuth against the real local AS**, including rejection on `iss` mismatch | auth hardening regresses |
| T-10 | Timeout and cancellation: slow tool cancelled, loop left clean | hang or task leak |
| T-11 | Oversized result is bounded, not OOM | result bounding regresses |
| T-12 | Context budget counts tool schemas **and** tool results | budget regresses |
| T-13 | Cap ordering: `tools.search` survives a `TOOL_COUNT_CAP` smaller than the MCP tool count | ordering regresses |
| T-14 | Wire-name registry warm before replay; `get__weather` and the 90-char name round-trip canonical→wire→canonical | the `to_wire_name` hazard returns |
| T-15 | Injection text from `hostile_server` never escapes the untrusted block | prompt-injection guard regresses |
| T-16 | Bridge behaviour unchanged after the definition-seam change | bridge regression |
| T-17 | Old session file (no `mcp_servers` key) still loads; MCP id never written to `tool_states` | `ToolName(k)` load crash |
| T-18 | One failing external definition provider does not empty `get_tool_definitions()` | isolation regresses |
| T-19 | MCP settings dialog closed while a worker runs does not crash | the PR #409 worker-destruction bug repeats |

---

## 6. Falsifiability — the rule that makes these count

**Every gate must be demonstrated RED against an intentionally broken
implementation before it counts.** Revert the behaviour, watch the test fail,
restore it. A gate that cannot fail is not a gate.

The ones most likely to be written vacuously, based on history:

- **T-2** — asserting a clean exit code proves nothing; assert the *PID tree*.
- **T-6** — assert no child process was spawned, and assert the **full argument
  string** appears in the rendered text, not that a dialog was constructed.
- **T-9** — the `iss`-mismatch case must actually reject; a test that only
  exercises the happy path is half a gate.
- **T-13** — a cap that never actually truncates gates nothing.
- **T-15** — assert the injection text is *inside* the delimiters, not merely
  that the call succeeded.

Further rules learned the hard way on this repo:

- Never assert on a mocked or stubbed return value in place of real behaviour.
- No unconditional `try/except: pass`, no blanket `pytest.skip`.
- Wrap the probe in `try/finally` so a falsification harness restores state even
  when the assertion fires.
- No fixed `sleep()` to synchronise — it races the suite. Wait on a condition.
- After any signature change, grep `def <method>` across `tests/` — a stub double
  hardcoding an old arity has survived two review rounds here before.
- Gate the whole slice **directory**, not a hand-picked file subset.

---

## 7. Running the suites

Tests **must** run in the Docker sandbox (host pytest is hook-blocked).

One file or a node-id set — this is the invocation that gives a clean signal:

```bash
python -m scripts.sandbox.docker_sandbox custom --extra-args "tests/mcp"
```

Module scope needs the `module` type; `-m` is ignored under `unit`:

```bash
just test module --module tests/mcp
```

Traps that have cost time on this repo:

- `just test <TYPE>` **always appends a fixed host-native pass afterwards**, so
  the tail of the output is host-native and unrelated failures scroll your real
  result off the top. Prefer the `docker_sandbox custom` form above.
- A silent run (`total=0`, no `pytest_finished`) is often a Docker
  `engine/restart`, not a test failure — grep the backend log before believing it.
- `docker image prune -a` **deletes the freshly built image** (45 GB rebuild).
  Use `prune -f`.
- Never `--timeout-method=thread` — it crashes.
- Subprocess-heavy tests native-crash under fd-capture; MCP stdio tests are
  subprocess-heavy, so watch for this specifically.
- Never gate the whole `tests/ui` tree (30-minute timeout, no signal). Run
  targeted slices. A blocking `QMessageBox` in an async callback hangs it
  forever; `tests/ui/conftest.py` has the modal guard.
- pytest-qt closes widgets before fixture teardown — join QThreads in
  `before_close_func`, or T-19's subject will crash the runner rather than fail
  cleanly.

**Regression proof:** `tests/core`, `tests/bridges`, `tests/providers` must pass
**unmodified**. If the cloud session edited any existing test, treat that as a
contract violation and review the edit before trusting the result. Measure
branch-caused failures the way it was done for PR #409: run the same file set at
`main` and at branch head, deterministically and isolated, and diff.

---

## 8. Live end-to-end verification (only possible here)

1. Launch the real app. Open the MCP settings dialog.
2. Add a real third-party **stdio** server (e.g. a filesystem server via `npx`)
   and a real **HTTP** server.
3. Confirm the consent dialog appears **before** anything launches, shows the
   command and every argument untruncated, names env vars without values, and
   carries the client-privilege warning. Cancel once and confirm no child
   process was created.
4. Approve, then press *Test connection* and confirm it reports the **real**
   discovered tool count.
5. In chat, ask something requiring the server. Verify: `tools.search` discovers
   it; the confirmation dialog shows the full arguments and the three approval
   scopes; the result renders with source attribution; the audit record is
   written.
6. Toggle a single tool off and confirm it disappears from the advertised set on
   the next turn.
7. Mutate the server's tool list and confirm re-prompting.
8. Verify the Windows keyring round-trip for a server secret, and that a
   keyring-unavailable condition makes the server **fail to start with a named
   error** rather than start unauthenticated.
9. Close the app. Confirm **zero orphaned child processes** and no console
   flash during the session.
10. Confirm `mcp.json` on disk contains no secret material.

---

## 9. What you do not do

- Do not write or refactor implementation code to make a gate pass. File the
  defect, and either hand it back or fix it deliberately as a separate,
  reviewed change with its own falsified test.
- Do not weaken a gate to get green.
- Do not edit the locked configs listed in §3.

---

## 10. Reporting

Produce, for each item in the cloud PR's claim list:

- **Verified** — the gate exists, was demonstrated red, and passes.
- **Failed** — with the defect, the failing gate, and the fix if you made one.
- **Unverifiable** — and why.

Record any deviation from the plan's design decisions that the implementation
made, and whether the deviation is acceptable. Close by stating explicitly which
of Phase 1 / 2 / 3 are complete and gated, and which are not.
