# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Reversible mapping between canonical dotted tool names and provider wire names.

OpenAI, Anthropic, Grok, and OpenRouter all require tool/function names to match ``^[A-Za-z0-9_-]{1,64}$``. Intellicrack's canonical tool-
function names are dotted (``"frida.spawn"``), which every one of those providers rejects. This module provides a stateless, collision-safe
bijection between the canonical dotted form used everywhere inside Intellicrack (routing, classification, confirmation, persistence) and the
provider-safe "wire" form that only ever appears at the provider boundary.

The primary mapping (``.`` <-> ``__``) is pure and requires no shared state. A registered fallback (deterministic hash suffix) exists only
for names that cannot round-trip through the primary mapping -- none of Intellicrack's current ~715 tool-function names hit it, but a local
or third-party model could echo an unexpected name, or a future tool name could collide with the ``__`` separator.
"""

from __future__ import annotations

import hashlib
import re
import threading
from typing import TYPE_CHECKING

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Iterable


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
    return wire if "__" not in wire else wire.replace("__", ".")


_wire_pair_to_canonical: dict[tuple[str, str], str] = {}


def rehydrate_wire_names(canonical_names: Iterable[str]) -> None:
    """Re-register the fallback wire names for a set of canonical names.

    Reversal of a hash-fallback wire name depends on the process-local
    registry that :func:`to_wire_name` populates as a side effect. A tool that
    appears only in *replayed history* -- never in the active set, which is
    exactly what tool search and deferred loading produce -- would otherwise
    never have been registered, and its wire name would reverse through the
    primary ``__`` -> ``.`` path to the wrong canonical name.

    The wire layer therefore calls this over the union of the active tools and
    every tool referenced in replayed history before it reverses any name. The
    mapping is a pure function of the canonical name, so nothing is persisted
    and a cold restart reproduces it exactly.

    Args:
        canonical_names: Canonical dotted tool-function names to register.
    """
    for canonical in canonical_names:
        to_wire_name(canonical)


def to_wire_pair(canonical: str) -> tuple[str, str]:
    """Split a canonical dotted name into an OpenAI namespace/function pair.

    Under OpenAI tool search the wire identity of a function is the pair
    ``(namespace, name)`` rather than a single string: ``ghidra.decompile``
    travels as namespace ``ghidra`` plus function ``decompile``. Intellicrack's
    dotted bridge names map onto that exactly.

    A name whose halves do not both satisfy the provider name rule -- or that
    carries more than one dot, where the split would be ambiguous on the way
    back -- falls back to an empty namespace plus the registered single-string
    wire name, which still round-trips.

    Args:
        canonical: Canonical dotted tool-function name.

    Returns:
        tuple[str, str]: The namespace (empty when the name is not namespaced)
        and the function name to send.
    """
    namespace, separator, name = canonical.partition(".")
    splittable = bool(separator) and bool(namespace) and bool(name) and "." not in name
    if splittable and is_valid_wire_name(namespace) and is_valid_wire_name(name):
        with _registry_lock:
            existing = _wire_pair_to_canonical.get((namespace, name))
            if existing is not None and existing != canonical:
                _logger.error(
                    "tool_wire_pair_collision",
                    namespace=namespace,
                    name=name,
                    existing=existing,
                    incoming=canonical,
                )
            else:
                _wire_pair_to_canonical[namespace, name] = canonical
                return namespace, name
    wire = to_wire_name(canonical)
    with _registry_lock:
        _wire_pair_to_canonical["", wire] = canonical
    return "", wire


def from_wire_pair(namespace: str, name: str) -> str:
    """Map an OpenAI namespace/function pair back to its canonical name.

    Checks the pair registry first, so a name that fell back to the hash form
    reverses correctly, then joins the pair. An empty namespace reverses
    through :func:`from_wire_name`, which is idempotent on names that are
    already canonical.

    Args:
        namespace: The namespace the provider reported, or the empty string.
        name: The function name the provider reported.

    Returns:
        str: The canonical dotted tool-function name.
    """
    with _registry_lock:
        registered = _wire_pair_to_canonical.get((namespace, name))
    if registered is not None:
        return registered
    if not namespace:
        return from_wire_name(name)
    return f"{namespace}.{from_wire_name(name)}"
