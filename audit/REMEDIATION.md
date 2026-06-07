# Test-Quality Remediation Log

## Scope

The audit (`audit/agent-01.md` … `agent-20.md`, indexed by `audit/INDEX.md`)
catalogued **529 findings** across the test suite — tests that passed without
being genuine, falsifiable quality gates: assertions against answer-shaped
inputs, `b""` / 4-byte "binaries", mocks of the component under test, presence
checks with no value assertions, and tests that could not go red if the
production code were corrupted.

Every finding was converted into (or removed in favour of) a real gate that:

- asserts a specific, independently-known expected value;
- drives real inputs (real PE / ELF / Mach-O, real `.hexpat` source, real
  Win32 handles, live `HexDocument` / `ProcessBridge` / interpreter
  instances) rather than answer-shaped fixtures;
- does not mock the thing under test;
- covers edge, error, and determinism cases; and
- would go red if the production behaviour it guards regressed.

Production source was touched **only** to add genuinely-missing functionality
that a correct gate exposed — never to force a fake gate green, and never to
delete a method binding.

## Verification bar (per file)

A file was considered remediated only when it produced **zero** findings from
each of `ruff check`, `basedpyright`, `pydoclint`, and `pydocstyle`, and its
`pytest` run passed (not skipped to hide breakage; environment-capability
skips — missing admin rights, absent symbol server, no loopback TCP, live
cloud-account limits — are legitimate and explicitly logged).

All tooling is run through the pinned environment:

```
pixi run --manifest-path D:/Intellicrack/pyproject.toml <tool> <files>
```

## Production fixes (genuine missing functionality exposed by a gate)

| File | Finding | Change |
| --- | --- | --- |
| `src/intellicrack/ui/panels/hex_editor/pattern_editor.py` | U12 — HexPat print sink never wired on first apply | First-construction path built the interpreter with `print_sink=None` and never attached the real sink; only *reused* interpreters were wired. `std::print` output from the first pattern apply was silently dropped. Now constructed with `print_sink=self._append_pattern_print_line`. |
| `src/intellicrack/sandbox/analysis.py` | C2 exfiltration detector ignored its own byte threshold | `_detect_exfiltration_patterns` gated on the send/receive ratio only; the `_EXFIL_THRESHOLD_BYTES` (1 MiB) constant defined for exfil was never applied, so a sub-megabyte API response with a high ratio was flagged as exfiltration. Now gated on `sent >= _EXFIL_THRESHOLD_BYTES` as well. |
| `src/intellicrack/sandbox/qemu.py` | guest-agent bootstrap typing | Annotation correction surfaced by the recovered guest-agent bootstrap test. |
| `pyproject.toml` + `pixi.lock` | F-0001 — dev tooling declared as runtime | `[project].dependencies` listed 113 packages, ~100 of them dev/test/docs/profiling tools, so `pip install intellicrack` pulled pytest, ruff, sphinx, mkdocs, tox, etc. as runtime requirements. Trimmed to the **23 packages production actually imports** (statically or via `importlib.import_module`), with the dev/test/docs/profile/ml tooling living in `[project.optional-dependencies]`. The pixi editable self-install now references `extras = ["dev", "test", "docs", "profile", "ml"]` so the development environment is unchanged. |

The runtime set was derived empirically from the AST of `src/intellicrack`
(top-level and nested `import` statements) plus an audit of every
`importlib.import_module(...)` call, not by hand-picking. `torch` /
`transformers` and the rest of the ML stack remain optional (`ml` extra); the
PDF-export `fpdf2` path stays optional with a graceful `ToolError` fallback.

## Final pytest resolutions

The closing pass resolved the last twelve failing test files. Several were
order-dependent flakes that `pytest-randomly` surfaced only on specific seeds;
each root cause was fixed rather than papered over.

| Test file | Root cause | Resolution |
| --- | --- | --- |
| `tests/test_providers/conftest.py` (+ 3 live Anthropic tests) | Org-disabled live account raised `ProviderError`, registering as a false negative | Added `"organization has been disabled/deactivated"` and `"account has been disabled"` to `_ACCOUNT_LIMIT_SIGNALS` so account-state preconditions skip like the existing billing/quota signals |
| `tests/test_providers/test_credential_loading.py` | Loader's documented `os.environ` fallback let the ambient `GOOGLE_API_KEY` satisfy the "missing key" case | Clear every provider key (and aliases) from `os.environ` via `monkeypatch` so the missing-key gate is unconditional |
| `tests/test_audit4/b5_modules_tab/test_modules_tab.py` | Patched a renamed symbol (`run_bridge_coroutine_async`) | Repointed to `run_bridge_coroutine_logged` and widened the fake to accept the `event` / `logger` / context kwargs |
| `tests/test_hexcore_e2e/test_bridge_transforms_deep.py` | `apply_transform` defaults to `in_place=True`; the comparison mutated the document between the direct and pipeline calls (XOR is involutive) and base64 raised on length change | Ran both comparisons with `in_place=False` |
| `tests/test_audit4/c9_hex_disassembly_debounce/test_follow_cursor_debounce.py` | Cursor offsets (`0xDEAD`, `0x1000`) sat at/beyond the 4096-byte document, so the production end-of-document guard correctly suppressed dispatch | Moved offsets in-bounds (`0x0DEA`, `0x0800`) |
| `tests/test_audit7/u12_hexpat_print_sink/test_ui_print_sink.py` | Gated the print-sink wiring fixed in `pattern_editor.py` | Passes against the corrected constructor |
| `tests/test_sandbox/test_analysis.py` | Beaconing timestamps used `ts_offset(60)` (invalid ISO seconds > 59); high-freq boundary assumed `> 10` where production fires at `>= 10`; exfil boundary gated the now-applied byte threshold | Fixed timestamps to ≤59s, aligned the high-freq boundary to `>= 10` (9 below / 10 at), and the exfil byte-threshold fix landed in production |
| `tests/test_bridges/test_process_bridge.py` | Three order-dependent flakes: (1) the shutdown test left the shared module bridge re-initialised on a dying loop → `WinError 6` self-pipe teardown error; (2) `search_pattern` asserted first-occurrence ordering of an 8-byte prefix that collides with other live-process copies; (3) `get_environment` raced the child's loader and read 0 vars under load | (1) Isolated to a function-local bridge shut down in `finally`; (2) search the full unique sentinel and assert exact membership + an off-by-one guard instead of result ordering; (3) poll `get_environment` until the child env block is populated |
| `tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py` | Malformed-JSON import hit `QMessageBox.warning` (modal) and hung headlessly | Wired the mixin's designed non-modal `_user_notifier` seam in the harness; the test also now asserts exactly one warning notification was surfaced |
| `tests/test_audit7/sandbox_windows/test_launch_failure_detection.py` | Already a genuine gate | Verified green (17 passed) |
| `tests/test_providers/test_openai_provider.py` | Already a genuine gate | Verified green (15 passed) |
| `tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py` | Gated the F-0001 `pyproject.toml` defect | Passes against the restructured manifest (23 runtime deps, dev tooling in extras) |

`tests/test_bridges/test_process_bridge.py` was re-run across six
`pytest-randomly` seeds (3, 7, 99, 555, 2024, 12345) with **182 passed / 9
skipped** every time, confirming the order-dependent flakes are resolved.

## Scaffolding (not part of the deliverable)

The orchestration helpers used to drive the remediation — `audit/_*.py`,
`audit/_*.json`, `audit/_*.log` — are working artifacts and are excluded from
the committed change set.
