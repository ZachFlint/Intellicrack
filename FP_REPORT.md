# False Positive Report - bridges/x64dbg.py

No false positives identified.

All 77 semgrep-logging findings reported in the initial scan were resolved by
applying canonical fix patterns. The single rule-edge case worth noting is
`intellicrack-logging-c5-exception-call-outside-except`, which originally fired
on `_logger.exception("disassembly_failed", ...)` inside an
`except Exception:` block followed by an `else:` clause. The rule's
`pattern-not-inside` formulations do not enumerate `try/except/else` shapes,
so the call was treated as outside an `except`. Rather than file this as a
false positive, the surrounding control flow was rewritten to a plain
`try/except` that returns `capstone_lines` after the `try`/`except`, which
satisfies both the rule and `ruff` `TRY300` while preserving the original
behaviour exactly: a successful disassembly path returns the populated list,
and any `Exception` raised during the read or disasm logs via `.exception()`
inside the active `except:` and returns an empty list.
