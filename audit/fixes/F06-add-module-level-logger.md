# F06 — Files missing module-level `_logger`

## Fix description

These files have operations that should be logged but contain no `_logger` definition. Per §3 #5 (missing module-level `_logger` is HIGH).

## Sites to fix

### `src/intellicrack/providers/huggingface.py`

- LLMProviderBase subclass; instance-level `self._logger` correctly bound at L184.
- However, **module-level helpers** and a `@staticmethod` cannot access `self._logger`:
  - `_extract_503_message` (static, L262)
  - `_convert_tool_choice` (L853)
  - `_parse_message_tool_calls` (L878)
  - `_extract_stream_delta` (L902)

Fix: add module-level `_logger` after L130 (or after the imports):

```python
from intellicrack.core.logging import get_logger
...
_logger = get_logger(__name__)
```

This does NOT conflict with `self._logger` in `HuggingFaceProvider`; the two coexist (`self._logger` for instance methods, `_logger` for static/module helpers).

Then wire `_logger.warning(...)` into the L287 silent except in `_extract_503_message` (see F14 for the actual log addition).

### `src/intellicrack/ui/panels/hex_editor/_bookmarks.py`

- 112 LOC, no `_logger`, no `get_logger` import.
- Contains document mutation operations (`document.add_bookmark`, `document.remove_bookmark`, `document.list_bookmarks`) that are §2.4 state mutations.
- Public methods `_on_add_bookmark` L51, `_on_remove_bookmark` L78, `_refresh_bookmarks` L100 perform real work.

Fix: add canonical logger:

```python
from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)
```

Then wrap document calls in try/except with logs (see F26 for the actual coverage additions):

- L74 `self.document.add_bookmark(...)` → log `bookmark_added` info
- L96 `self.document.remove_bookmark(...)` → log `bookmark_removed` info
- L89/L106 `self.document.list_bookmarks()` → wrap with try/except, log on failure

### `src/intellicrack/ui/panels/hex_editor/_calculator.py`

- 241 LOC, no `_logger`, no `get_logger` import.
- Several silent `except` blocks (L106, L140, L150, L226, L240) that swallow `(struct.error, OverflowError, ValueError)`.

Fix: add canonical logger:

```python
from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)
```

Then add debug logs in each except (these are defensive UI fallbacks but per §2.2 must log):

- L106 `_logger.debug("calc_input_parse_failed", text=text, error=str(exc))`
- L140 `_logger.debug("calc_int_overflow", label=label, value=value)`
- L150 `_logger.debug("calc_float_pack_failed", label=label)`
- L226/L240 `_logger.debug("calc_ieee754_pack_failed", label=label)`

## Acceptance criteria

- [ ] `huggingface.py` has module-level `_logger` placed after imports
- [ ] `_bookmarks.py` has module-level `_logger` and document mutations are wrapped/logged
- [ ] `_calculator.py` has module-level `_logger` and all silent excepts emit debug logs
- [ ] No `self._logger` references in `_bookmarks.py` or `_calculator.py` (they aren't LLMProvider subclasses)
- [ ] Existing `self._logger` in `huggingface.py` retained (LLMProvider exception)
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
