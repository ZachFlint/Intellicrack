# False Positive Report — Unit 12 (UI Panels Top-Level)

This report documents semgrep-logging findings within the 16 in-scope files
that remain after this unit's fixes. Each entry is a pre-existing finding that
either (a) was present in the base scan but is intrinsic to the rule and
satisfied semantically, or (b) was outside the original 99-finding scope and
is unaffected by the unit's edits.

## Pre-existing rule-intrinsic findings (in-scope files)

### `cutter_panel.py:1131` — `intellicrack-logging-d8-binary-write-without-log`

The d8 rule fires unconditionally on every `*.write_bytes(...)` call (no
`pattern-not` clauses). The rule message itself states the finding is a
"reviewable non-issue" when an adjacent `_logger.info(...)` exists. This unit
added `_logger.info("cutter_patch_bytes_requested", binary_path=..., offset=...,
byte_count=...)` immediately preceding the call, satisfying the rule's
documented reviewer criterion. The pattern still matches the bare AST node and
cannot be suppressed without rule-config changes (which are out of scope).
This finding was present in the base scan (line 1106 prior to additions).

### `ghidra_panel.py:2539` — `intellicrack-logging-d8-binary-write-without-log`

Identical situation to cutter_panel.py: `bridge.write_bytes(addr, hex_data)` is
preceded by `_logger.info("ghidra_write_bytes_requested", binary_path=...,
address=..., byte_count=...)`. The rule fires unconditionally. Was present in
the base scan (line 2515 prior to additions).

## Pre-existing findings outside the 99-finding scope

These findings are reproduced by a current scoped semgrep run but were NOT
in the unit's seed JSON (`reports/json/semgrep_findings.json`). They reflect
code that was unchanged by this unit's edits.

### `hxd_panel.py:200` — `intellicrack-logging-e5-warning-announces-success`

`_logger.warning("hxd_not_installed")`. The event-name regex matches the
`installed` suffix, but semantically this is a precondition-failure warning
("HxD is NOT installed"), not a success announcement. The line was unchanged
by this unit; pre-existing in main repo.

### `hxd_panel.py:240` — `intellicrack-logging-e5-warning-announces-success`

Identical pattern to `hxd_panel.py:200`; second use of the same event in a
different start path. Pre-existing in main repo, unchanged by this unit.

### `script_manager.py:840` — `intellicrack-logging-e4-critical-outside-allowlist`

`QMessageBox.critical(self, "Error", ...)` — this is a Qt UI dialog method
(severity-styled message box), not a logger call. The e4 rule's
`pattern: $L.critical(...)` matches the AST shape regardless. The line was
unchanged by this unit; pre-existing in main repo and not present in the
seed JSON.
