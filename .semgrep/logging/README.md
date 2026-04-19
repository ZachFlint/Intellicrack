# Intellicrack logging Semgrep ruleset

A strict, retrofit-oriented ruleset that enforces comprehensive structured
logging on every operation inside Intellicrack. The rules run as part of
`just semgrep` (alongside the Semgrep registry) and can be validated
standalone with `just semgrep-test-logging`.

The ruleset is deliberately aspirational — Tier 2/3 rules are expected to
fire on existing code. Each finding is an upgrade target, not a false
positive.

## How to run

- `just semgrep` - full scan (registry rules + logging rules) over `src/`.
- `just semgrep-test-logging` - validate the rules against the paired test
  fixtures in this directory. Exits non-zero on any mismatch.

`just semgrep-test-logging` exists because `semgrep --test` has an RPC
race on Windows / semgrep 1.159 (JSON decode error). `validate.py` uses
the text output and performs the same annotation contract.

## Layout

```
.semgrep/logging/
  01-logger-identity.yml + .py         # Category A - logger acquisition
  02-event-names.yml + .py             # Category B - event-name quality
  03-structured-fields.yml + .py       # Category C - kwarg discipline
  04-coverage-gaps.yml + .py           # Category D - missing logging
  05-severity-levels.yml + .py         # Category E - wrong level
  06-sensitive-data.yml + .py          # Category F - secret leakage
  07-anti-patterns.yml + .py           # Category G - bad practice
  08-flow-correlation.yml + .py        # Category H - correlation
  09-intellicrack-domain.yml + .py     # Category I - Intellicrack-specific
  10-meta-suppressions.yml + .py       # Category J - suppression hygiene
  validate.py                          # permanent test harness
  README.md
```

Every rule YAML has a paired Python fixture annotated with
`# ruleid: <rule>` (line must trigger) and `# ok: <rule>` (line must
NOT trigger). The validator cross-checks every annotation against the
semgrep scan result.

## Severity tiers

- **ERROR** - correctness + security. Near-zero FP by design. Safe to
  block CI on.
- **WARNING** - quality + coverage. Expected to fire on existing code;
  each finding is a retrofit target.
- **INFO** - opinionated stylistic. Informational only.

## Categories

| Category | File                        | Rules | Tier  |
|----------|-----------------------------|-------|-------|
| A        | 01-logger-identity.yml      | 6     | 1     |
| B        | 02-event-names.yml          | 10    | 1-3   |
| C        | 03-structured-fields.yml    | 8     | 1-3   |
| D        | 04-coverage-gaps.yml        | 14    | 1-3   |
| E        | 05-severity-levels.yml      | 7     | 2     |
| F        | 06-sensitive-data.yml       | 6     | 1     |
| G        | 07-anti-patterns.yml        | 10    | 1-3   |
| H        | 08-flow-correlation.yml     | 5     | 2-3   |
| I        | 09-intellicrack-domain.yml  | 9     | 2     |
| J        | 10-meta-suppressions.yml    | 3     | 1     |

## Intellicrack logging conventions enforced

- Module logger: `_logger = get_logger(__name__)` from
  `intellicrack.core.logging`. No `logging.getLogger`.
- Provider classes may hold `self._logger = get_logger(__name__)`.
- Event name: snake_case `verb_object` string literal. No f-strings,
  `.format`, `%`-formatting, concatenation, or sentences. No generic
  terms (`error`, `failed`, `done`, `start`, ...).
- Structured kwargs: all variable data as keyword arguments. Reserved
  LogRecord keys (`name`, `message`, `msg`, `levelname`, `filename`,
  `module`, `lineno`, `funcName`, `exc_info`, ...) forbidden.
- `.exception()` only inside `except:` blocks; no `error=str(e)` on
  `.exception()` (traceback already captured).
- Severity semantics: info for progress, warning for problem, error
  for handled failure, exception for captured traceback, critical for
  fatal-only.
- Context kwargs: whenever the enclosing function receives `pid`,
  `process_name`, `binary_path`, `target`, `address`, `size`,
  `module_name`, `offset`, `session_id`, `bridge`, `tool_name`,
  `provider`, `script_id`, `probe_id`, `monitor_id`, or `hook_id` as
  a parameter, log calls must pass it.
- Destructive + cross-boundary operations (subprocess, network, file
  write, destructive fs, memory patch, Frida script load/unload,
  disassembler invocation, provider completion, credential store,
  session state change, sandbox start/stop, unpack/unprotect) must
  have an adjacent log call.
- No secrets in logs: `password`, `api_key`, `token`, `bearer`,
  `authorization`, `credential`, `private_key`, `cookie`,
  `os.environ[...]` values, HTTP headers/cookies/bodies, raw bytes
  payloads, or high-entropy literals.
- No `# noqa` suppressing `G*` / `LOG*` / `TRY4*` / `BLE*` rules.
- No `print()`, no `traceback.print_exc()`, no `logging.disable(...)`.

## Triaging findings

When `just semgrep` surfaces a new finding:

1. **Check the tier.** ERROR = real bug, fix before merge. WARNING =
   quality upgrade, triage at your pace. INFO = style nit.
2. **Read the rule message.** Every rule explains the *why*, the
   canonical Intellicrack convention it encodes, and a concrete
   example of the correct form.
3. **Upgrade the code.** Replace the lazy/incomplete pattern with the
   convention the message suggests. Re-run `just semgrep` to confirm.
4. **Never `# noqa` a logging finding.** Rule J1 will flag that
   anyway. If the rule is genuinely wrong for your case, fix the
   rule or the fixture and re-validate with
   `just semgrep-test-logging`.

## Adding a new rule

1. Pick the right category file (or propose a new one).
2. Write the rule in YAML. Use `paths.exclude` with `**/` anchoring
   to avoid Semgrep v2 semgrepignore warnings.
3. Append positive and negative fixtures to the paired `.py` file
   with `# ruleid:` / `# ok:` annotations.
4. Run `just semgrep-test-logging` - must PASS.
5. Run `just semgrep` - observe new findings on existing code;
   document any retrofit required.

## Known semgrep quirks on Windows

- `semgrep --test` errors with RPC JSON decoding. Use
  `just semgrep-test-logging` instead (text-output based).
- `--json` / `--sarif` output formats intermittently return
  `<ERROR: missing output>` due to a race in semgrep-core's formatter.
  The `justfile` semgrep recipe works because it writes JSON via its
  own pipeline script; for ad-hoc queries, use `--text`.
- `settings<random>.yml` files accumulate in `~/.semgrep` when
  scanning across many config files. `validate.py` cleans them
  before every run.

## Regex authoring notes

- semgrep `metavariable-regex` uses `re.fullmatch`. Wrap patterns
  with `.*...*` or explicit `^...$` anchors that account for the full
  value. Simple alternation like `success|done` will NOT match
  `op_success` - write `^(.*_)?(success|done)(_.*)?$` instead.
- `"$METAVAR"` in a pattern captures string *content* without
  surrounding quotes. Regex matching sees the inner text.
- `f"$METAVAR"` f-string metavariables behave differently from
  regular string metavariables. Prefer pattern-either with concrete
  method names (`$L.info(..., $K=f"...", ...)`) over a generic
  `$L.$LVL(..., $K=f"$FMT", ...)` when the generic form fails.
