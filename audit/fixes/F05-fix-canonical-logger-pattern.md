# F05 — Canonical logger pattern violations

## Fix description

Per §1, modules must use:

- Module-level `_logger = get_logger(__name__)` from `intellicrack.core.logging`
- Instance-level `self._logger` permitted ONLY in `LLMProviderBase` subclasses

Sites below violate one or both rules.

## Sites to fix

### Inline `structlog.get_logger(...)` instead of canonical helper

`src/intellicrack/__init__.py:L87`

Current:

```python
def __getattr__(name: str) -> Any:
    ...
    structlog.get_logger("intellicrack").debug("lazy_import_resolved", attribute=name)
```

Fix: add module-level `_logger`:

```python
from intellicrack.core.logging import get_logger
_logger = get_logger(__name__)
```

Then call `_logger.debug("lazy_import_resolved", attribute=name)` inside `__getattr__`. Remove the `import structlog` if no other use remains.

### `self._logger` on non-LLMProviderBase classes

`src/intellicrack/providers/discovery.py`

| Severity | Line | Class |
|----------|-----:|-------|
| MEDIUM | 107 | `DiscoveryCache` |
| MEDIUM | 463 | `ModelDiscovery` |

`src/intellicrack/providers/registry.py`

| Severity | Line | Class |
|----------|-----:|-------|
| MEDIUM | 75 | `ProviderRegistry` |

Fix: replace the instance attribute with module-level `_logger`:

Before:

```python
class DiscoveryCache:
    def __init__(self, ...):
        ...
        self._logger = get_logger(__name__)
```

After:

```python
_logger = get_logger(__name__)  # at module level, after imports

class DiscoveryCache:
    def __init__(self, ...):
        ...
        # no self._logger
```

Then replace every `self._logger.X(...)` call inside these classes with `_logger.X(...)`.

### `bridges/base.py:L344` (LOW — documented exception, no fix required)

`ToolBridgeBase.__init__` sets per-instance `self._logger = get_logger(f"bridges.{...}").bind(...)`. This is justified because the logger name encodes the concrete subclass. Document the exception in `bridges/base.py` docstring and keep as-is.

## Acceptance criteria

- [ ] `__init__.py:L87` uses canonical module-level `_logger`
- [ ] `discovery.py` and `registry.py` use module-level `_logger`; no `self._logger` on non-LLMProviderBase classes
- [ ] Class docstring on `ToolBridgeBase` mentions the instance-logger pattern is intentional for subclass-name encoding
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
- [ ] No new module-level `structlog` imports
