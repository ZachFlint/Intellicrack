# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared sandbox log-line helpers for network primitives and YARA matches.

This module exposes the small pure-Python primitives that both :mod:`intellicrack.sandbox.windows` and :mod:`intellicrack.sandbox.qemu` use
while parsing in-guest monitor logs and post-execution YARA results.

The helpers are deliberately untouched by the per-backend log-parser methods (which live in ``sandbox.windows`` and ``sandbox.qemu``); they
operate purely on strings and YARA match objects so they can be reused across both sandbox flavours without dragging any sandbox state.
"""

from __future__ import annotations

from typing import Any, Final, Literal


YARA_MATCH_MIN_FIELDS: Final[int] = 3
"""Minimum tuple length for a usable ``yara.Match`` strings entry.

Each entry is expected to be ``(offset, identifier, data)``; entries with fewer than three positional members are skipped.
"""


def split_addr_port(value: str) -> tuple[str, int]:
    """Split an ``address:port`` literal into its components.

    Handles bracketed IPv6 forms (``[::1]:443``) as well as the common
    ``ipv4:port`` shape produced by the in-guest network monitor. When
    the value cannot be parsed the address is returned verbatim and the
    port falls back to ``0``.

    Args:
        value: String of the form ``address:port`` or ``[ipv6]:port``.

    Returns:
        tuple[str, int]: Parsed address and port; port is ``0`` if
        unparseable or absent.
    """
    if not value:
        return ("", 0)
    if value.startswith("[") and "]:" in value:
        addr, _, port_str = value.partition("]:")
        addr = addr.lstrip("[")
        return (addr, safe_int(port_str))
    addr, sep, port_str = value.rpartition(":")
    return (addr, safe_int(port_str)) if sep else (value, 0)


def coerce_protocol(value: str) -> Literal["tcp", "udp", "icmp", "other"]:
    """Normalize a protocol label to the canonical sandbox vocabulary.

    Inputs are matched case-insensitively; anything that is not exactly
    ``tcp``, ``udp``, or ``icmp`` is reported as ``other`` so callers
    never observe an unknown protocol token.

    Args:
        value: Raw protocol string from the monitor log.

    Returns:
        Literal["tcp", "udp", "icmp", "other"]: One of the canonical
        protocol labels.
    """
    lowered = value.strip().lower()
    if lowered == "tcp":
        return "tcp"
    if lowered == "udp":
        return "udp"
    return "icmp" if lowered == "icmp" else "other"


def infer_direction(state: str) -> Literal["inbound", "outbound"]:
    """Infer the network-activity direction from a TCP/UDP state string.

    States that imply a server-side socket (``listen``/``bound``) are
    classified as inbound; every other state, including ``established``,
    ``time_wait`` and friends, is treated as outbound.

    Args:
        state: Raw state string from the network log.

    Returns:
        Literal["inbound", "outbound"]: ``inbound`` for listen/bound
        states, ``outbound`` otherwise.
    """
    normalized = state.strip().lower()
    return "inbound" if normalized in {"listen", "bound"} else "outbound"


def safe_int(value: str) -> int:
    """Convert a candidate numeric string to an ``int``, defaulting to 0.

    Accepts integer literals as well as strings that round-trip through
    ``float`` (e.g., ``"3.0"``). Empty input or non-numeric values
    return ``0`` so caller code can rely on a usable integer without
    extra branching.

    Args:
        value: Candidate numeric string.

    Returns:
        int: Parsed integer, or ``0`` if ``value`` is empty or not
        numeric.
    """
    s = value.strip()
    if not s:
        return 0
    try:
        return int(s)
    except (TypeError, ValueError):
        try:
            return int(float(s))
        except (TypeError, ValueError):
            return 0


def safe_float(value: str) -> float:
    """Convert a candidate numeric string to a ``float``, defaulting to 0.0.

    Empty input or non-numeric values return ``0.0`` so caller code can
    rely on a usable float without extra branching.

    Args:
        value: Candidate numeric string.

    Returns:
        float: Parsed float, or ``0.0`` if ``value`` is empty or not
        numeric.
    """
    s = value.strip()
    if not s:
        return 0.0
    try:
        return float(s)
    except (TypeError, ValueError):
        return 0.0


def format_yara_match(m: object, source: str, scan_type: str) -> dict[str, Any]:
    """Normalize a YARA match object into a serializable dictionary.

    The function is intentionally tolerant of yara-python's optional
    fields: missing attributes default to empty strings, an empty tag
    list, or no matched strings, so the returned shape is stable for
    downstream tooling.

    Args:
        m: YARA match object as produced by ``yara-python`` (typically a
            ``yara.Match`` instance).
        source: Origin file path that produced the match.
        scan_type: Either ``files`` or ``memory`` describing the scan
            input.

    Returns:
        dict[str, Any]: Dictionary describing the rule, namespace, tags,
        matched strings, source path, and scan type.
    """
    rule: str = getattr(m, "rule", "")
    namespace: str = getattr(m, "namespace", "")
    tags: list[str] = list(getattr(m, "tags", []))
    raw_strings: list[Any] = list(getattr(m, "strings", []))
    formatted: list[dict[str, Any]] = []
    for s in raw_strings:
        if len(s) >= YARA_MATCH_MIN_FIELDS:
            data_val: Any = s[2]
            formatted.append(
                {
                    "offset": s[0],
                    "identifier": s[1],
                    "data": data_val.hex() if isinstance(data_val, bytes) else str(data_val),
                },
            )
    return {
        "rule": rule,
        "namespace": namespace,
        "tags": tags,
        "strings": formatted,
        "source": source,
        "scan_type": scan_type,
    }


__all__: list[str] = [
    "YARA_MATCH_MIN_FIELDS",
    "coerce_protocol",
    "format_yara_match",
    "infer_direction",
    "safe_float",
    "safe_int",
    "split_addr_port",
]
