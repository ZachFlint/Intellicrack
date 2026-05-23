# F09 — Remove forbidden "ImHex" literal

## Fix description

Project memory (`feedback_no_imhex_name.md`) forbids the literal string "ImHex" in code, comments, identifiers, and docstrings. Use "hexpat" or "pattern language" instead. This is not a logging finding but was surfaced by shard 09; including here for organization.

## Sites to fix

### `src/intellicrack/core/hexpat/interpreter.py:L39`

Current:
```python
_IMHEX_PATTERNS_DIR = ...
```

Fix: rename identifier and update all references:
```python
_HEXPAT_PATTERNS_DIR = ...
```

Use `rg "_IMHEX_PATTERNS_DIR" src/intellicrack/` to find every reference and update them.

### `src/intellicrack/core/hexpat/stdlib.py:L63`

Current (docstring or comment):
```python
"""Create a deterministic RNG seeded like ImHex's runtime."""
```

Fix: rewrite to remove the ImHex reference:
```python
"""Create a deterministic RNG seeded for the hexpat runtime."""
```

## Verification

This regex should return zero matches across `src/intellicrack/`:

```
rg -i "imhex" src/intellicrack/
```

## Acceptance criteria

- [ ] `_IMHEX_PATTERNS_DIR` renamed and all callers updated
- [ ] `stdlib.py:L63` docstring rewritten
- [ ] `rg -i "imhex" src/intellicrack/` returns zero matches
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
- [ ] No new docstring violations from `pydoclint` / `pydocstyle`
