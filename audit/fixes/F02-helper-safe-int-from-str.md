# F02 — Inline parser silent swallow: `_safe_int_from_str` helper

## Fix description

The pattern `except ValueError: return None/0/""/continue/pass` in inline integer/hex parsers silently swallows parse failures. Per §2.2 every except must log at least at debug. Spread across bridges, hexpat stdlib, and PE/ELF reader helpers.

Closes ~25 HIGH findings by introducing one helper and rolling it out.

## Helper template

Add to a shared util module (suggest `src/intellicrack/bridges/_parse_helpers.py` for bridge sites; `src/intellicrack/core/hexpat/_parse_helpers.py` for hexpat sites — keep them local to avoid cross-package coupling):

```python
from typing import Final

from intellicrack.core.logging import get_logger

_logger: Final = get_logger(__name__)


def safe_int_from_str(
    value: str,
    *,
    base: int = 0,
    context: str,
    default: int | None = None,
) -> int | None:
    """Parse an integer from a string, logging at debug on failure.

    Args:
        value: String to parse (e.g. "0x401000", "42", "0b1011").
        base: Numeric base passed to int(); 0 = auto-detect.
        context: Snake_case identifier of the call site (e.g. "x64dbg_coerce_address").
        default: Value to return when parsing fails; None by default.

    Returns:
        Parsed int, or ``default`` when the string cannot be parsed.
    """
    try:
        return int(value, base)
    except (ValueError, TypeError) as exc:
        _logger.debug(
            "safe_int_parse_failed",
            context=context,
            raw=value,
            base=base,
            error=str(exc),
        )
        return default
```

Use sites become:

```python
ip_value = safe_int_from_str(rip_result, base=16, context="x64dbg_wait_for_ip")
if ip_value is None:
    continue
```

## Sites to fix

### `src/intellicrack/bridges/x64dbg.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 416 | `_safe_int_or_none()` swallows `ValueError` |
| HIGH | 2501 | `_coerce_address()` returns 0 silently |
| HIGH | 3247 | `_verify_breakpoint_applied()` per-entry parse |
| HIGH | 5036 | `_wait_for_instruction_pointer()` hex parse |
| HIGH | 5085 | `_lookup_annotation_text()` annotation address parse |
| HIGH | 5555 | `get_labels()` label address parse |
| HIGH | 5634 | `get_comments()` comment address parse |
| HIGH | 8045 | `_coerce_hex_int()` returns None silently |

### `src/intellicrack/bridges/process.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 6461 | `_parse_pe_com_descriptor` `struct.error` → `None` silently |
| HIGH | 6516 | `_read_cor20_version` same pattern |
| HIGH | 6576 | `_read_metadata_version` same pattern |

### `src/intellicrack/core/hexpat/stdlib.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 1816 | `_time_to_local` silent swallow returning `PatternValue(value=0)` |
| HIGH | 1834 | `_time_to_utc` same pattern |
| HIGH | 1863 | `_time_format` silent swallow |
| HIGH | 2745 | `_format_string._replace` silent fallback |
| HIGH | 2750 | `_format_string` silent fallback on regex/lookup failure |

### `src/intellicrack/ui/panels/hex_editor/_templates.py` (PE/ELF struct reads)

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 377 | `_on_auto_bookmark_structure` magic read |
| HIGH | 419 | `_bookmark_pe_structure` DOS header read |
| HIGH | 439 | `_bookmark_pe_structure` COFF header read |
| HIGH | 489 | `_bookmark_pe_sections` per-section read |
| HIGH | 513 | `_bookmark_elf_structure` EI_CLASS read |
| HIGH | 529 | 64-bit ELF header read |
| HIGH | 545 | ELF program/section header counts read |
| HIGH | 561 | 32-bit ELF header read |

### `src/intellicrack/ui/panels/hex_editor/_calculator.py`

| Severity | Line | Context |
|----------|-----:|---------|
| MEDIUM | 106 | `_on_convert()` ValueError → tree-widget message |
| MEDIUM | 140 | `(struct.error, OverflowError)` integer pack — needs logger (see F06) |
| MEDIUM | 150 | `(struct.error, OverflowError)` float pack — needs logger |

NOTE: `_calculator.py` lacks module-level `_logger` — fix F06 first (add module-level `_logger`), then convert these sites with the helper.

### `src/intellicrack/bridges/process.py` (other silent struct.error sites)

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 3519 | `_parse_type_info_buffer` string decoder returns `""` |
| HIGH | 5115 | `get_mitigation_policies` per-policy probe |
| HIGH | 5770 | `get_mitigation_policy` SEHOP mask |
| HIGH | 5830 | `get_extension_policy` query |

(These don't all fit `_safe_int_from_str` — some need a more general `_safe_call(fn, *, context, default)` wrapper. Consider extending the helper module.)

## Acceptance criteria

- [ ] Helper added with type hints, docstring
- [ ] All ~25 inline parser swallow sites replaced with helper call (or equivalent logged variant)
- [ ] No `except ValueError: return None/0/continue/pass` blocks remaining in the listed files
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
- [ ] Helper unit-tested for happy path + all silent-return cases
