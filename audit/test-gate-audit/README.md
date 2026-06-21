# Intellicrack Test-Gate Audit

**Date:** 2026-06-13
**Scope:** Every test file in the repository read in full and judged against one
question per test:

> *If the real Intellicrack functionality under test were broken, deleted, or
> made to return garbage, would this test FAIL?*

A test that stays green regardless of whether the underlying functionality works
is **not a production-release gate** and is flagged here. Methodology, the
non-gate taxonomy (N1–N10), and severity definitions live in
[`_RUBRIC.md`](_RUBRIC.md). This audit is **flag-only** — no test or source file
was modified.

---

## Aggregate results

| Metric | Count |
|---|---|
| Test files audited | **407** (+ all empty `__init__.py` package markers, which contain no tests) |
| Test functions examined | **~4,435** |
| Genuine gates | **4,131 (93.1%)** |
| Flagged non-gates | **304 (6.9%)** |
| — CRITICAL (can essentially never fail) | **33** |
| — HIGH (fails to gate the named behavior) | **37** |
| — MEDIUM (weak/partial gate) | **152** |
| — LOW (real gate, should be hardened) | **82** |

**Headline:** the suite is strong in aggregate — ~93% of tests are genuine
falsifiable gates that drive real binaries, real tool bridges, and real engines
with assertions checked against independent oracles. The 304 flagged tests
concentrate in a small number of files; **33 CRITICAL tests can never fail** and
must be fixed first because they provide false confidence.

---

## Per-area breakdown

| Area report | Files | Tests | Gates | Flagged | C | H | M | L |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| [test_hexcore_e2e (part 1)](test_hexcore_e2e_part1.md) | 36 | 430 | 395 | 35 | 1 | 11 | 13 | 10 |
| [test_hexcore_e2e (part 2)](test_hexcore_e2e_part2.md) | 34 | 558 | 548 | 10 | 1 | 4 | 0 | 5 |
| [test_ui (part 1)](test_ui_part1.md) | 31 | 274 | 256 | 18 | 0 | 0 | 7 | 11 |
| [test_ui (part 2 + log_viewer)](test_ui_part2.md) | 25 | 287 | 261 | 26 | 12 | 1 | 13 | 0 |
| [test_providers (part 1)](test_providers_part1.md) | 24 | 268 | 235 | 33 | 2 | 9 | 21 | 1 |
| [test_providers (part 2)](test_providers_part2.md) | 22 | 215 | 192 | 23 | 6 | 1 | 16 | 0 |
| [test_bridges (part 1)](test_bridges_part1.md) | 18 | 451 | 437 | 14 | 0 | 0 | 8 | 6 |
| [test_bridges (part 2)](test_bridges_part2.md) | 19 | 318 | 296 | 22 | 3 | 0 | 14 | 5 |
| [test_core (part 1)](test_core_part1.md) | 17 | 184 | 152 | 32 | 0 | 0 | 4 | 28 |
| [test_core (part 2)](test_core_part2.md) | 18 | 246 | 240 | 6 | 0 | 0 | 1 | 5 |
| [test_audit4 (group 1)](test_audit4_group1.md) | 19 | 122 | 109 | 13 | 0 | 0 | 9 | 4 |
| [test_audit4 (group 2)](test_audit4_group2.md) | 15 | 86 | 79 | 7 | 1 | 0 | 6 | 0 |
| [test_audit4 (group 3)](test_audit4_group3.md) | 13 | 137 | 131 | 6 | 0 | 0 | 5 | 1 |
| [test_audit7 (group 1)](test_audit7_group1.md) | 13 | 78 | 73 | 5 | 0 | 0 | 5 | 0 |
| [test_audit7 (group 2)](test_audit7_group2.md) | 13 | 84 | 81 | 3 | 0 | 0 | 1 | 2 |
| [test_audit3](test_audit3.md) | 24 | 178 | 159 | 19 | 1 | 6 | 11 | 1 |
| [test_audit5](test_audit5.md) | 22 | 145 | 130 | 15 | 0 | 1 | 13 | 1 |
| [test_sandbox + test_hexpat](test_sandbox_and_hexpat.md) | 23 | 318 | 308 | 10 | 1 | 4 | 4 | 1 |
| [credentials + root + ui/core + scripts](misc_credentials_root_scripts.md) | 21 | 56 | 49 | 7 | 5 | 0 | 1 | 1 |
| **TOTAL** | **407** | **4,435** | **4,131** | **304** | **33** | **37** | **152** | **82** |

---

## CRITICAL findings (fix first — these tests can never fail)

These are always-green regardless of source state. They give false release
confidence and must be converted into real gates (or deleted) before any one is
trusted.

### A production defect masked by a fake gate
- **`tests/test_hexcore_e2e/test_bridge_alignment_color.py:200`**
  `test_set_alignment_grid` asserts `result is True` against
  `HexEditorBridge.set_alignment_grid`, which is **hardcoded `return True`**
  (`src/.../hex_editor.py:5984`). The grid value is never stored or read back —
  the production setter is a no-op and the test rubber-stamps it. *Real defect,
  not just a weak test.*

### Tests that reimplement production logic and assert on their own copy (N10)
- **`tests/core/test_process_cleanup.py:320,346,380,409`** — four QEMU pidfile
  retry tests re-implement the retry loop inline and assert on the local copy;
  `QemuSandbox._read_pidfile_once`/retry loop is never called. One
  (`test_qemu_pidfile_retry_exhausted_returns_none`) even asserts `None` while
  the production contract now raises `SandboxError`.
- **`tests/core/test_process_cleanup.py:147`**
  `test_sandbox_temp_wsb_file_cleaned_up` writes and unlinks its own temp file,
  never invoking the production cleanup it claims to validate.
- **`tests/test_audit4/c7_hex_bookmarks_notify/test_bookmark_notify.py`** — the
  harness hand-rolls the post-dialog tail instead of calling `_on_add_bookmark`;
  five "add" tests verify the harness. Line **296**
  (`test_add_bookmark_no_notify_when_state_holder_absent`) additionally has **no
  assertion at all** (N1).

### No-assertion / "did not raise" tests (N1)
- **`tests/test_hexcore_e2e/test_hexpat_complex_patterns.py:388`**
  `test_cast_negative_to_signed` — runs `execute_bytes`, discards the result, no
  assertion; a sign-extension regression cannot fail it.
- **`tests/test_bridges/test_x64dbg_events.py:183,227`** —
  `test_handle_event_with_no_callbacks`, `test_unknown_event_does_not_crash`:
  no assertions.
- **`tests/test_ui/test_vnc_widget.py`** — five "when disconnected / no
  framebuffer / partial data" tests assert nothing; three "protocol format"
  tests (`test_pointer_event_format`, `test_key_event_format`,
  `test_framebuffer_update_request_format`) pack/unpack with `struct` entirely
  inside the test and never call Intellicrack code — they validate `struct`, not
  the RFB bridge. (11 flagged in this file; this is the single worst offender.)

### Tautological / stdlib-not-Intellicrack tests (N4)
- **`tests/test_bridges/test_x64dbg.py:66`** `test_bridge_instantiation` —
  `assert bridge is not None`; **`:374`** `test_disassemble_requires_capstone`
  executes zero assertions whenever capstone is installed (the normal case).
- **`tests/test_providers/test_provider_bugfixes.py`** — `TestHuggingFaceJsonDecode`
  asserts `httpx.Response.json()` raises (tests httpx);
  `TestOpenRouterPricingConversion` asserts `float("N/A")` raises and
  re-implements the production try/except inside the test; plus import-only /
  construction-smoke / `dict.get` tests. (6 CRITICAL in this file.)
- **`tests/test_providers/test_agentic_capabilities.py`**
  `test_ollama_models_report_accurate_tool_support` — `isinstance(x, set)`,
  trivially true regardless of capability metadata.

### Swallowed-failure tests (N2)
- **`tests/test_providers/test_local_xpu_e2e.py`** `test_empty_message_list_handled`
  — wraps the call in `contextlib.suppress(...)` with no assertion; crash and
  success accepted equally.
- **`tests/test_sandbox/...test_realcov_07b_compiler_pragmas.py`**
  `test_at_least_one_vendor_pattern_compiles_to_static_json` — broad
  `except (ValueError, RecursionError, KeyError): continue` plus a
  `compiled >= 1` bar lets static codegen regress on nearly the entire vendor
  corpus while staying green.
- **`tests/test_audit3/...`** `test_get_version_x64dbg_uses_pe_when_available` —
  `version is None or isinstance(...)` passes on total failure.

---

## Cross-cutting anti-patterns (the 271 HIGH/MEDIUM/LOW findings)

The non-CRITICAL findings recur in a handful of shapes; fixing the pattern fixes
clusters at once:

1. **Source-text proxies (N9).** Asserting `inspect.getsource(...)` contains or
   omits a substring, or that generated script text contains a token, instead of
   driving the behavior. Heavy in `test_audit3/test_xml_gen.py` (6),
   `test_audit5/u5_ui_mainwindow` (signal-wiring source scans),
   `test_audit7_group1` QEMU start tests, `test_providers_cloud_audit1`
   (retry-with-backoff grep). A code-gen / wiring regression that preserves the
   string passes.
2. **Accepts-both-outcomes (N7).** `assert r is None or isinstance(r, ...)`,
   `assert status in ("ok", "error")`, "both outcomes are valid" docstrings.
   Concentrated in `test_win32_embed.py`, provider streaming/tool-choice tests,
   and the Windows-sandbox create tests — on capability-absent CI they gate
   nothing.
3. **Vacuously-satisfiable conditionals (N6).** Real assertion guarded by
   `if result:` / `if pending:` / iterating a possibly-empty `list_models()`,
   so an empty/falsy real result silently skips the check. The provider
   `list_models()` field tests and several hexcore search/disassembly
   upper-bound (`len(r) <= cap`) tests.
4. **Existence/type-only behavior tests (N8).** `hasattr` / `callable` /
   `isinstance(r, list)` where the test name promises a value or behavior. Large
   cluster in `test_font_manager.py`, `test_icon_manager.py`,
   provider capability-flag checks, and hex-editor dispatch-surface tests.
5. **Logging convenience-call smoke tests (N1/N8).** `test_core/test_logging.py`
   (28 LOW) calls the production logging helper and asserts nothing or only
   `hasattr` — a regression in *what* is logged (event name, dropped/renamed
   structured field) is invisible. Fix: `structlog.capture_logs` + assert event
   name and exact fields.
6. **Skip-on-real-failure (N3).** A few tests `pytest.skip` when the capability
   they themselves trigger fails to materialize (real C2/capture analysis in
   `test_sandbox`, vendor-pattern interpreter smoke in `test_audit5/u3`),
   absorbing a genuine regression as a skip.

---

## What is explicitly **not** a problem

Each report has an "Acceptable skips" section. Legitimate environment-capability
skips were reviewed and **not** flagged: missing admin/elevation, no loopback
TCP, absent OS services (Spooler, ETW `TraceEvent.dll`), Windows-only Win32
surfaces on non-Windows, missing external tool binaries (Ghidra/Cutter/rizin/
frida/QEMU), optional native `intellicrack_hexcore` build, GPU/XPU hardware
absence, and live-cloud-provider tests skipping without API keys/billing. These
are correct production gates: they require the capability when present and
decline only when the host genuinely cannot provide it.

Mock usage was scrutinized for N5 (mock-validates-mock) and the **majority was
judged genuine** — most doubles substitute only the external transport boundary
(network client, named pipe, OS clipboard, UAC `ShellExecuteW`, external tool
stdout) while the real Intellicrack logic under test runs unmodified. Only the
specific cases listed in each report's flagged section mock the unit under test
itself.

---

## Recommended remediation order

1. **The 33 CRITICAL tests** — convert to real gates or delete. Start with
   `test_set_alignment_grid` (exposes a real no-op production setter) and the
   `test_process_cleanup.py` reimplemented-loop cluster.
2. **The 37 HIGH tests** — they name a behavior they do not gate; rewrite the
   assertion to require the named outcome (kill the `if`-guard / both-outcomes
   disjunction).
3. **N9 source-text proxies** — replace with behavioral assertions using the
   monkeypatch/`capture_logs` seams already present in those files.
4. **N8 existence-only & N1 logging smoke tests** — harden to value/field
   assertions; delete the ones fully duplicated by a stronger sibling (most LOW
   findings are redundant duplicates and can simply be removed).
