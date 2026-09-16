# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Reversible mapping between canonical dotted tool names and provider wire names.

OpenAI, Anthropic, Grok, and OpenRouter all require tool/function names to
match ``^[A-Za-z0-9_-]{1,64}$``. Intellicrack's canonical tool-function names
are dotted (``"frida.spawn"``), which every one of those providers rejects.
This module provides a stateless, collision-safe bijection between the
canonical dotted form used everywhere inside Intellicrack (routing,
classification, confirmation, persistence) and the provider-safe "wire" form
that only ever appears at the provider boundary.

The primary mapping (``.`` <-> ``__``) is pure and requires no shared state.
A registered fallback (deterministic hash suffix) exists only for names that
cannot round-trip through the primary mapping -- none of Intellicrack's
current ~715 tool-function names hit it, but a local or third-party model
could echo an unexpected name, or a future tool name could collide with the
``__`` separator.
"""

from __future__ import annotations

import hashlib
import re
import threading

from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)

_WIRE_NAME_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")

_FALLBACK_PREFIX_MAX_CHARS = 40
_FALLBACK_DIGEST_SIZE_BYTES = 8
_MAX_WIRE_NAME_CHARS = 64

_wire_to_canonical: dict[str, str] = {}
_registry_lock = threading.Lock()


def is_valid_wire_name(name: str) -> bool:
    """Check whether a name satisfies the strictest provider name rule.

    OpenAI, Anthropic, Grok, and OpenRouter all constrain tool names to
    ``^[A-Za-z0-9_-]{1,64}$``; this is the intersection of every supported
    provider's constraint, so a name that passes this check is safe to send
    to any of them.

    Args:
        name: Candidate wire name to validate.

    Returns:
        bool: ``True`` if ``name`` matches the provider name rule.
    """
    return bool(_WIRE_NAME_PATTERN.fullmatch(name))


def _sanitize_prefix(canonical: str) -> str:
    """Build a human-readable, wire-safe prefix from a canonical name.

    Args:
        canonical: Canonical dotted tool-function name.

    Returns:
        str: A truncated, provider-safe prefix derived from ``canonical``.
    """
    sanitized = re.sub(r"[^A-Za-z0-9_-]", "_", canonical)
    return sanitized[:_FALLBACK_PREFIX_MAX_CHARS]


def _register_fallback(canonical: str, wire: str) -> str:
    """Record a fallback wire name in the reversal registry, detecting collisions.

    Args:
        canonical: Canonical dotted tool-function name being mapped.
        wire: Deterministically derived wire name for ``canonical``.

    Returns:
        str: ``wire``, unchanged, once safely registered.

    Raises:
        ValueError: If ``wire`` is already registered for a *different*
            canonical name. This can only happen on a genuine hash collision
            and must never be silently resolved, since that would corrupt
            reversal for one of the two colliding tools.
    """
    with _registry_lock:
        existing = _wire_to_canonical.get(wire)
        if existing is not None and existing != canonical:
            message = f"Wire name collision: {wire!r} already maps to canonical {existing!r}, cannot also map {canonical!r}"
            _logger.error("tool_wire_name_collision", wire=wire, existing=existing, incoming=canonical)
            raise ValueError(message)
        _wire_to_canonical[wire] = canonical
    return wire


def _fallback_wire_name(canonical: str) -> str:
    """Derive a deterministic wire name for a canonical name that failed the primary mapping.

    The result is a pure function of ``canonical`` alone -- no salt, no
    insertion-order disambiguation -- so a cold restart or a different
    process reproduces the identical wire name, keeping history replay
    consistent across sessions.

    Args:
        canonical: Canonical dotted tool-function name.

    Returns:
        str: A deterministic, provider-safe, registered wire name.
    """
    digest = hashlib.blake2b(canonical.encode("utf-8"), digest_size=_FALLBACK_DIGEST_SIZE_BYTES).hexdigest()
    prefix = _sanitize_prefix(canonical)
    wire = f"{prefix}_{digest}" if prefix else digest
    if len(wire) > _MAX_WIRE_NAME_CHARS:
        wire = wire[-_MAX_WIRE_NAME_CHARS:]
    return _register_fallback(canonical, wire)


def to_wire_name(canonical: str) -> str:
    """Map a canonical dotted tool-function name to a provider-safe wire name.

    Attempts the pure ``.`` -> ``__`` substitution first and self-checks that
    it round-trips (``wire.replace("__", ".") == canonical``) and satisfies
    :func:`is_valid_wire_name`. Only names containing ``__`` already, or
    exceeding 64 characters after substitution, fail this check; those fall
    back to a deterministic registered mapping.

    Args:
        canonical: Canonical dotted tool-function name (e.g. ``"frida.spawn"``).

    Returns:
        str: A wire name safe to send to any supported provider.
    """
    candidate = canonical.replace(".", "__")
    if candidate.replace("__", ".") == canonical and is_valid_wire_name(candidate):
        return candidate
    return _fallback_wire_name(canonical)


def from_wire_name(wire: str) -> str:
    """Map a provider wire name back to its canonical dotted tool-function name.

    Checks the fallback registry first (covers hash-suffixed names), then
    falls back to the pure ``__`` -> ``.`` substitution. Names with no
    ``__`` and no registry entry are returned unchanged, which makes this
    function idempotent on names that are already canonical -- a local model
    that echoes a canonical dotted name verbatim is handled safely.

    Args:
        wire: Wire name as received from a provider tool-call response.

    Returns:
        str: The canonical dotted tool-function name.
    """
    with _registry_lock:
        registered = _wire_to_canonical.get(wire)
    if registered is not None:
        return registered
    if "__" not in wire:
        return wire
    return wire.replace("__", ".")
