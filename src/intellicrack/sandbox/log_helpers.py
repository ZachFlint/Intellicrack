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

from typing import TYPE_CHECKING, Any, Final, Literal


if TYPE_CHECKING:
    from pathlib import Path


YARA_TARGET_FILES: Final[str] = "files"
YARA_TARGET_MEMORY: Final[str] = "memory"
YARA_SCAN_TARGETS: Final[tuple[str, str]] = (YARA_TARGET_FILES, YARA_TARGET_MEMORY)
YARA_NON_ARTIFACT_SUFFIXES: Final[frozenset[str]] = frozenset({".txt", ".log"})
MEMORY_DUMP_PREFIX: Final[str] = "memdump_"

ERR_YARA_UNKNOWN_TARGET: Final[str] = "unknown scan target {target!r}; expected one of {expected}"
ERR_YARA_NO_MEMORY_DUMP: Final[str] = (
    "no guest memory dump to scan in {path}; run dump_memory() on the running guest before scanning memory"
)
ERR_YARA_NO_ARTIFACTS: Final[str] = (
    "no collected artifacts to scan in {path}; the guest produced no dropped-file archive and the output directory holds nothing scannable"
)


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


def scannable_output_files(output_dir: Path) -> list[Path]:
    """Collect the guest artifacts a file-target YARA scan should read.

    The dropped-file archive is the preferred input, but a guest that never
    dropped anything still leaves collected artifacts in the output directory.
    Monitor transcripts and guest memory dumps are excluded: the transcripts are
    the sandbox's own text output rather than the guest's, and the dumps belong
    to the memory target.

    Args:
        output_dir: Shared-folder output directory the guest writes into.

    Returns:
        list[Path]: Regular files worth scanning; empty when there are none.
    """
    if not output_dir.is_dir():
        return []
    return [
        entry
        for entry in output_dir.rglob("*")
        if entry.is_file() and entry.suffix.lower() not in YARA_NON_ARTIFACT_SUFFIXES and not entry.name.startswith(MEMORY_DUMP_PREFIX)
    ]


def format_yara_string_instances(entry: object) -> list[dict[str, Any]]:
    """Flatten one matched YARA string into one record per occurrence.

    ``yara.Match.strings`` holds a ``StringMatch`` per string identifier, and
    each of those holds a ``StringMatchInstance`` per place the string was
    found, carrying the offset and the bytes that matched. A string found four
    times therefore produces four records.

    Args:
        entry: A ``yara.StringMatch`` as produced by ``yara-python``.

    Returns:
        list[dict[str, Any]]: One ``offset``/``identifier``/``data`` record per
        occurrence, with byte data hex-encoded so the result stays
        JSON-serialisable.
    """
    identifier = str(getattr(entry, "identifier", ""))
    instances: list[object] = list(getattr(entry, "instances", []))
    records: list[dict[str, Any]] = []
    for instance in instances:
        data: object = getattr(instance, "matched_data", b"")
        records.append(
            {
                "offset": getattr(instance, "offset", 0),
                "identifier": identifier,
                "data": data.hex() if isinstance(data, bytes) else str(data),
            },
        )
    return records


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
    raw_strings: list[object] = list(getattr(m, "strings", []))
    formatted: list[dict[str, Any]] = []
    for entry in raw_strings:
        formatted.extend(format_yara_string_instances(entry))
    return {
        "rule": rule,
        "namespace": namespace,
        "tags": tags,
        "strings": formatted,
        "source": source,
        "scan_type": scan_type,
    }


__all__: list[str] = [
    "ERR_YARA_NO_ARTIFACTS",
    "ERR_YARA_NO_MEMORY_DUMP",
    "ERR_YARA_UNKNOWN_TARGET",
    "MEMORY_DUMP_PREFIX",
    "YARA_NON_ARTIFACT_SUFFIXES",
    "YARA_SCAN_TARGETS",
    "YARA_TARGET_FILES",
    "YARA_TARGET_MEMORY",
    "coerce_protocol",
    "format_yara_match",
    "format_yara_string_instances",
    "infer_direction",
    "safe_float",
    "safe_int",
    "scannable_output_files",
    "split_addr_port",
]
