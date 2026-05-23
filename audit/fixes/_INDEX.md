# Logging Audit — Fix Index

Per-fix-type markdowns for the 770 findings from the 20-shard logging audit. Each file groups all findings sharing the same mechanical fix.

**See also**:

- `D:\Intellicrack\audit\AUDIT_CRITERIA.md` — the strict rules the audit enforced
- `D:\Intellicrack\audit\MASTER_REPORT.md` — aggregate report with executive summary
- `D:\Intellicrack\audit\shard-NN-*.md` — per-shard raw findings (20 files)

## Tier 1 — Helper-driven cross-cutting fixes (highest leverage)

| # | File | What it closes |
|---|------|----------------|
| F01 | [Typed-exception passthrough → `_log_and_reraise`](F01-helper-log-and-reraise.md) | ~35 HIGH across providers + bridges + yara_scanner + hexpat_compiler |
| F02 | [Inline parser silent swallow → `_safe_int_from_str`](F02-helper-safe-int-from-str.md) | ~25 HIGH across x64dbg + process + hexpat stdlib + hex_editor templates |
| F03 | [Bridge invocation entry/exit → `_run_async_logged` wrapper](F03-helper-run-async-logged.md) | ~150 MEDIUM across all UI tool panels |
| F04 | [UI panel input parse → `self._invalid_input` helper](F04-helper-panel-invalid-input.md) | ~22 HIGH across frida/ghidra/x64dbg/hex_editor panels |

## Tier 2 — Canonical-pattern fixes

| # | File | What it closes |
|---|------|----------------|
| F05 | [Canonical logger pattern violations](F05-fix-canonical-logger-pattern.md) | `__init__.py` inline `structlog.get_logger` + `self._logger` on non-LLMProvider classes |
| F06 | [Add module-level `_logger` to 3 files](F06-add-module-level-logger.md) | `huggingface.py`, `_bookmarks.py`, `_calculator.py` |
| F07 | [Flatten `extra={...}` kwargs in qemu.py](F07-flatten-extra-kwargs.md) | ~20 MEDIUM |

## Tier 3 — Forbidden constructs

| # | File | What it closes |
|---|------|----------------|
| F08 | [Remove `contextlib.suppress`](F08-remove-contextlib-suppress.md) | 1 HIGH (x64dbg.py L2564) |
| F09 | [Remove "ImHex" literal](F09-remove-imhex-literal.md) | 2 LOW (hexpat interpreter + stdlib) |

## Tier 4 — Style conversions

| # | File | What it closes |
|---|------|----------------|
| F10 | [`.warning(..., error=str(exc))` → `.exception(...)` in non-re-raising blocks](F10-warning-to-exception.md) | ~25 LOW + 2 HIGH (traceback preservation) |

## Tier 5 — Silent except log additions (grouped by area)

| # | File | What it closes |
|---|------|----------------|
| F11 | [bridges/ghidra.py mutation method excepts](F11-silent-except-bridges-ghidra-mutations.md) | 14 HIGH + 1 LOW |
| F12 | [bridges/process.py kernel/Win32 probes](F12-silent-except-bridges-process.md) | 10 HIGH + 1 LOW |
| F13 | [bridges/installer.py + named_pipe + frida + x64dbg](F13-silent-except-bridges-other.md) | 5 + 4 + 2 + 4 = 15 HIGH |
| F14 | [core/ silent excepts (transform_pipeline + logging + process_manager + hexpat)](F14-silent-except-core.md) | 12 HIGH + several MEDIUM |
| F15 | [sandbox/qemu.py + windows.py silent excepts](F15-silent-except-sandbox.md) | 6 HIGH |
| F16 | [providers misc silent excepts (not F01)](F16-silent-except-providers-misc.md) | 7 HIGH |
| F17 | [ui/panels/process_panel/ silent excepts](F17-silent-except-ui-process-panel.md) | 7 HIGH + 1 MEDIUM + 1 LOW |
| F18 | [ui/panels/hex_editor/ submodule silent excepts](F18-silent-except-ui-hex-editor.md) | ~14 HIGH (post-F02/F04) |

## Tier 6 — Coverage additions

| # | File | What it closes |
|---|------|----------------|
| F19 | [Entry/exit logs on public methods](F19-entry-exit-public-methods.md) | ~80 MEDIUM across bridges + core + credentials |
| F20 | [Pre-call logs around external operations (subprocess/file/network)](F20-external-op-pre-call-logs.md) | ~40 MEDIUM |
| F21 | [GUI workflow milestones (app.py + tools.py)](F21-gui-workflow-milestones.md) | ~30 MEDIUM |
| F22 | [OAuth + HTTP probe entry logs](F22-oauth-http-probe-logs.md) | ~17 MEDIUM |
| F23 | [Win32 / ctypes call pre-call logs](F23-win32-ctypes-pre-call-logs.md) | ~10 MEDIUM |
| F24 | [Session dataclass mutator logs](F24-session-dataclass-mutator-logs.md) | 8 MEDIUM + 5 LOW |
| F25 | [VNC send-side protocol exchange logs](F25-vnc-protocol-send-logs.md) | 7 MEDIUM |
| F26 | [`execute_script` security-sensitive surface logs](F26-execute-script-security-logs.md) | 3 HIGH (most security-sensitive surface) |
| F27 | [Fix `run_bridge_coroutine_async(..., None, None)` anti-pattern](F27-async-bridge-none-error-callbacks.md) | 9 MEDIUM (threads_tab) |
| F28 | [Sandbox public operation entry logs](F28-sandbox-public-op-entry-logs.md) | 22 MEDIUM (qemu + windows) |
| F29 | [Splash screen startup stage transition logs](F29-splash-screen-stage-logs.md) | 5 LOW (startup observability) |
| F30 | [State-mutating bridge ops promoted to info level](F30-state-mutating-bridge-ops-info-level.md) | Cross-references F03; covers the high-impact subset |

## Recommended execution order

The order minimizes rework — earlier fixes set up helpers that later fixes depend on.

### Phase 1 — Helpers + canonical (1-2 days)

1. F05 — Fix `__init__.py` inline logger (1 line)
2. F06 — Add module-level `_logger` to 3 files (3 lines)
3. F08 — Remove `contextlib.suppress` (1 site)
4. F09 — Remove "ImHex" literal (2 sites)
5. F01 — Add `_log_and_reraise` helper + roll out (~35 sites)
6. F02 — Add `_safe_int_from_str` helper + roll out (~25 sites)
7. F04 — Add `self._invalid_input` helper + roll out (~22 sites)
8. F03 — Add `run_bridge_coroutine_logged` wrapper + roll out (~150 sites)

**End of Phase 1**: HIGH count drops from 157 to ≈30; MEDIUM count drops by ~150.

### Phase 2 — Targeted HIGH fixes (2-3 days)

1. F11 — bridges/ghidra.py mutations
2. F12 — bridges/process.py probes
3. F13 — bridges/installer + named_pipe + frida + x64dbg
4. F14 — core silent excepts
5. F15 — sandbox silent excepts
6. F16 — providers misc
7. F17 — process_panel silent excepts
8. F18 — hex_editor submodule silent excepts
9. F07 — Flatten qemu.py `extra={...}`
10. F10 — `.warning` → `.exception` conversions
11. F26 — execute_script security logs

**End of Phase 2**: HIGH count ≈ 0; MEDIUM count drops further.

### Phase 3 — Coverage additions (5-7 days)

1. F19 — Entry/exit on public methods
2. F20 — External op pre-call logs
3. F21 — GUI workflow milestones
4. F22 — OAuth + HTTP probe entry logs
5. F23 — Win32 / ctypes pre-call logs
6. F24 — Session dataclass mutator logs
7. F25 — VNC send-side protocol logs
8. F27 — async_bridge None-callback anti-pattern
9. F28 — Sandbox public op entry logs
10. F29 — Splash screen stage logs
11. F30 — State-mutating bridge ops → info level

**End of Phase 3**: MEDIUM count < 50; LOW count addressed in cleanup.

## Verification commands

After each phase:

```powershell
# Lint
pixi run ruff check src/intellicrack/

# Type check
pixi run basedpyright src/intellicrack/

# Docstrings
pixi run pydoclint src/intellicrack/
pixi run pydocstyle src/intellicrack/

# Forbidden patterns
rg "contextlib\.suppress" src/intellicrack/                # should be 0
rg "logging\.getLogger" src/intellicrack/                  # should be 0 outside core/logging.py
rg "_logger\.[a-z]+\(f['\"]" src/intellicrack/             # should be 0 (f-string in log call)
rg -i "imhex" src/intellicrack/                            # should be 0
rg "^\s*print\(" src/intellicrack/                         # should be 0 outside generated script strings
rg "# noqa.*[Tt]ry" src/intellicrack/                      # should be 0
rg "# type:\s*ignore" src/intellicrack/                    # should be 0 for logging issues
```
