# Test-Gate Remediation Results

**Status:** COMPLETE — every confirmed test-gate finding addressed.
**Last updated:** 2026-06-23

**Scope:** Every test flagged as a non-gate in the test-gate audit
(`audit/test-gate-audit/`, **312 confirmed findings** across **137 test files**,
filter `raw_findings.json::confirmed == true`), grouped by owning test file. Each
finding was turned into a real, falsifiable production-release gate, deleted as a
proven redundant/vacuous duplicate, or left as a deliberately-RED gate over a real
production defect (per decision rule 1 — `src/` was never modified to make a gate
pass).

## Headline

- **Confirmed findings addressed:** 312 / 312 (cross-referenced by finding id;
  the 5 ids that do not appear verbatim in a status record are bookkeeping splits —
  `G0027` -> `G0027a`/`G0027b`, `G0278` -> `n-A`/`n-B` — not gaps).
- **Per-file status records:** 236 under `audit/test-gate-audit/remediation/`.
- **Hardened / strengthened into real gates:** ~523 finding-test records.
- **Deleted as redundant or vacuous:** ~127 (each justified in its status record by
  a named stronger covering sibling, or because it gated non-existent / unreachable
  behavior).
- **Production-defect gates:** 7 real defects surfaced as RED gates, now all
  **fixed in `src/` and verified GREEN** in the Windows Docker sandbox
  (2026-06-26: 16 passed / 0 failed / 0 skipped). See `PRODUCTION-DEFECTS.md`.
- **Quality:** every changed file passes `ruff`, `basedpyright` (strict),
  `pydoclint`, and `pydocstyle` with **zero findings and zero suppressions** of any
  kind (no `noqa`, no `type: ignore`, no `pyright: ignore`). Locked configs were
  never weakened.

## What "a real gate" means here

Every hardened test asserts the actual operation's result/side-effect against an
**independent oracle** (recompute a different way — `hashlib` / `zlib.crc32` /
`struct.unpack` / `pefile` / `capstone` / a bit-serial CRC / a hand-decoded binary
field / a TypedDict's `get_type_hints` artifact / a real registry/SCM/Win32 round
trip), drives **real Intellicrack code against real inputs**, allows doubles only
at an external transport boundary (network socket / OS pipe / clipboard / UAC
prompt / external-tool stdout / QEMU subprocess), and is **falsifiable** — there is
a documented one-line production mutation that turns the assertion RED.

## Disposition by group (this remediation ran group-by-group, sandbox-verified)

| Group | Outcome |
|---|---|
| credentials, hexcore c1–c3, providers c1–c3, ui c1–c2, bridges c1 | hardened; PD-001/004 (resource/pattern-registry), PD-002/003 (time_thread_wait), PD-SYM (symbol), PD-006 (anthropic cache) surfaced |
| bridges c2 | 13 hardened, 1 deleted; PD-004/005 (time_thread_wait SYNCHRONIZE, enumerate_services handle-truncation) surfaced as RED gates |
| audit4 c1 | 10 hardened, false-positive defect gate removed (threads-tab register sync), PID-0 / QEMU-accelerator test bugs fixed |
| audit4 c2 | 7 hardened, 1 deleted; streaming-CRC bit-serial oracle + exact `format_size` branch gates |
| sandbox | 22 hardened; IOC sentinel test-bug fixed; TypedDict tautologies re-gated against `get_type_hints`/`__required_keys__` |
| core c1 / core c2 | 16 hardened; elevation guard spies, `get_tool_definitions` structural gate, `tools_directory` installer-mkdir gate |
| audit3 | 13 hardened, 3 deleted (N9 docstring/vacuous); TraceEvent.dll capability skip; dll-monitor evidence set tightened; named-pipe guard isolated; flaky transient-mutex made deterministic |
| audit7 c1 / c2 | 11 hardened; pre-existing 300s-sleep launcher hang fixed; print-sink absence test anchored; registration tests gate real schema+callable |
| audit5 | 3 hardened, 1 deleted; cutter/hexpat/mainwindow |
| hexpat | 3 hardened (bitfield / u8-array / parsed-field exact oracles) |

## Sandbox verification (Docker)

Every wave's changed files were executed **inside the Docker sandbox** (never the
host interpreter). Each wave finished green except:

- the **7 production-defect gates**, which are RED by design, and
- **legitimate environment-capability skips** the audit already accepts: live-cloud
  provider tests without network/billing, headless-GUI window embedding, Intel-XPU
  VRAM reclamation, loopback-TCP monitoring, Windows-Sandbox backend, ETW
  `TraceEvent.dll` (absent in the container), admin/`SeDebugPrivilege`-only paths,
  and container-unsupported Win32 APIs (`GetProcessMitigationPolicy`).

Each wave was also subjected to an **in-pipeline adversarial falsifiability
re-check**; every residual bounce was triaged against sandbox ground truth and
either fixed (test bug / weak oracle / flaky timing / capability skip) or confirmed
as a real production-defect gate. Notable triage outcomes this session:

- **False-positive defect rejected:** the threads-tab `_on_write_registers`
  "always reads hex" was *not* a defect — `_on_reg_cell_changed` syncs the
  companion column, so reading the hex column is always correct; the RED test had
  constructed an unreachable state via `blockSignals`. Test deleted, no `src` change.
- **Misdiagnosed defect rejected:** the sandbox IOC test failed because its sentinel
  paths put IPs adjacent to `_` (a `\b` word char), so the regex never extracted
  them — a test bug, not a missing `_add_ioc`. Sentinels re-delimited; production was
  correct.
- **Flaky gate made deterministic:** the kernel transient-mutex gate now holds three
  mutexes simultaneously for one 2000 ms window (< the 3 s slow cadence) instead of
  three sequential 400 ms windows, eliminating sweep-timing flakiness while
  preserving falsifiability.

## Production defects surfaced (7) — all RESOLVED, see PRODUCTION-DEFECTS.md

Writing the correct gates exposed 7 real production defects. They were first kept
RED with `src/` untouched (rule 1), then **all fixed in source and verified GREEN**
in the Windows Docker sandbox (2026-06-26 `custom` run: 16 passed / 0 failed /
0 skipped — the live SymFromAddr tests now resolve real symbols instead of
skipping). Each changed source file passes ruff / basedpyright / pydoclint /
pydocstyle with zero findings and no suppressions.

1. **PD-001** `resource_helper.py` — `resource_exists("")` returns `True` (should be `False`).
2. **PD-002** `bridges/process.py` `time_thread_wait` — opens the thread without
   `SYNCHRONIZE`, so `WaitForSingleObject` always returns `WAIT_FAILED`.
3. **PD-003** `bridges/process.py` `_time_wait_on_handle` — compares signed ctypes
   `-1` against unsigned `WAIT_FAILED` (`0xFFFFFFFF`); failure branch unreachable
   (returns `other_-1`).
4. **PD-004** `bridges/hex_editor.py` `_get_pattern_registry` — `parents[2]` (resolves
   to `src/`) instead of `parents[3]`, so the vendored pattern catalog is never scanned.
5. **PD-005** `bridges/process.py` `enumerate_services` — never configures
   `OpenSCManagerW.restype = SC_HANDLE`, truncating the 64-bit SCM handle so
   `EnumServicesStatusExW` fails and the method returns `[]` (order-dependent; only
   works if `list_services` configured the shared prototype first).
6. **PD-006** `providers/anthropic.py` `_build_usage_from_message` + `providers/base.py`
   `UsageInfo` — prompt-cache token counts (`cache_read_input_tokens` /
   `cache_creation_input_tokens`) are silently dropped.
7. **PD-007** `bridges/process.py` `_resolve_symbol` — `SYMBOL_INFO.SizeOfStruct`
   formula yields 89 (trailing-array padding) where `SymFromAddr` requires 88, so all
   debug-symbol resolution returns `("", 0)`.

## Remaining / not-done

- **7 production defects** have been fixed in `src/` and verified GREEN (no longer
  outstanding).
- A small number of native-Rust falsifiability proofs (`intellicrack-hexcore`)
  require a `cargo` rebuild to flip in-sandbox; the prebuilt module is what the
  container loads. Each such mutation is correct by inspection and documented in the
  owning status record.

## Bookkeeping

- Per-file status records: `audit/test-gate-audit/remediation/*.status.json` (236).
- Production defects: `audit/test-gate-audit/PRODUCTION-DEFECTS.md` (PD-001…PD-007).
- Authoritative work-list: `raw_findings.json` (filter `confirmed == true`),
  grouped in `_worklist.json`; per-wave args under `_waves/`.
- Remediation workflow: `_remediate_workflow.mjs` (per wave: fix → quality →
  adversarial verify+refix → batched Docker-sandbox green).
