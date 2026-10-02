# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Making a server's argument schema safe to put in front of a model.

A tool's ``inputSchema`` is the server's own text, and it travels to the model on every request that advertises the tool: property
descriptions and titles, enumeration and constant values, defaults, examples, even property names. Every one of those strings is a place
to hide an instruction or a terminal escape.

The schema is rewritten before it is advertised. Annotation text -- descriptions, titles, comments, formats and any keyword Intellicrack
does not interpret -- is cleaned and bounded. Strings that must reach the server exactly as the server wrote them -- property names,
``required`` entries, definition names, enumeration and constant values, defaults and examples -- cannot be cleaned without breaking the
call, so an unsafe one is replaced by a visible alias instead, and :meth:`SanitizedSchema.restore_arguments` maps every alias the model
sends back to the original before the call is delivered. A ``pattern`` is rewritten into an equivalent ECMA-262 pattern whose unsafe
characters are written as ``\uXXXX`` escapes, so it still matches exactly what it matched before.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from intellicrack.bridges.json_schema import MAX_SCHEMA_NESTING, truncate_schema_nesting
from intellicrack.core.json_payload import is_json_array, is_json_object, map_json_strings
from intellicrack.core.logging import get_logger
from intellicrack.core.untrusted_text import (
    clean_untrusted_label,
    escape_identifier,
    forged_marker_spans,
    identifier_needs_alias,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


_logger = get_logger(__name__)


SCHEMA_TEXT_LIMIT: Final[int] = 2048
"""Longest description, title or other annotation kept from a schema."""

_ALIAS_SUFFIX: Final[str] = "~{index}"

_NAME_MAP_KEYWORDS: Final[frozenset[str]] = frozenset({"properties", "dependentSchemas", "$defs", "definitions"})
"""Keywords whose keys are names that must survive and whose values are subschemas."""

_PATTERN_MAP_KEYWORDS: Final[frozenset[str]] = frozenset({"patternProperties"})
"""Keywords whose keys are patterns and whose values are subschemas."""

_SCHEMA_LIST_KEYWORDS: Final[frozenset[str]] = frozenset({"anyOf", "oneOf", "allOf", "prefixItems"})

_SCHEMA_KEYWORDS: Final[frozenset[str]] = frozenset({
    "items",
    "additionalItems",
    "additionalProperties",
    "unevaluatedItems",
    "unevaluatedProperties",
    "contains",
    "propertyNames",
    "not",
    "if",
    "then",
    "else",
})

_VALUE_KEYWORDS: Final[frozenset[str]] = frozenset({"const", "default"})
"""Keywords holding one instance value."""

_VALUE_LIST_KEYWORDS: Final[frozenset[str]] = frozenset({"enum", "examples"})
"""Keywords holding a list of instance values."""

_REFERENCE_KEYWORDS: Final[frozenset[str]] = frozenset({"$ref", "$dynamicRef"})

_NAME_LIST_KEYWORDS: Final[frozenset[str]] = frozenset({"required"})

_PATTERN_KEYWORDS: Final[frozenset[str]] = frozenset({"pattern"})

_BMP_LIMIT: Final[int] = 0xFFFF
_SURROGATE_BASE: Final[int] = 0x10000
_HIGH_SURROGATE: Final[int] = 0xD800
_LOW_SURROGATE: Final[int] = 0xDC00
_SURROGATE_BITS: Final[int] = 10
_SURROGATE_MASK: Final[int] = 0x3FF


def _ecma_escape(character: str) -> str:
    r"""Write one character as the ECMA-262 escape that matches exactly it.

    Args:
        character: The character.

    Returns:
        str: ``\uXXXX``, or a surrogate pair of them for a character outside
        the Basic Multilingual Plane, which is what a pattern without the
        ``u`` flag matches it as.
    """
    code = ord(character)
    if code <= _BMP_LIMIT:
        return f"\\u{code:04X}"
    offset = code - _SURROGATE_BASE
    high = _HIGH_SURROGATE + (offset >> _SURROGATE_BITS)
    low = _LOW_SURROGATE + (offset & _SURROGATE_MASK)
    return f"\\u{high:04X}\\u{low:04X}"


def _is_unsafe_in_pattern(character: str) -> bool:
    """Report whether a pattern character must be written as an escape.

    Args:
        character: The character.

    Returns:
        bool: ``True`` for every control, format or unassigned code point and
        for the Unicode line and paragraph separators.
    """
    return unicodedata.category(character)[0] == "C" or character in {"\u2028", "\u2029"}


def sanitize_pattern(pattern: str) -> str:
    r"""Rewrite a pattern so it carries nothing unsafe but matches exactly as before.

    Every unsafe character becomes its ``\uXXXX`` escape, and so does every
    letter of a stretch that reads as a fence marker. A letter or unsafe
    character is always a literal outside an escape sequence, so writing it
    as an escape changes nothing it matches; metacharacters are never
    touched. An unsafe character written as an identity escape (a backslash
    before it) loses the backslash along with the change, since ``\uXXXX``
    is already an escape; a backslash that starts any other escape keeps the
    character after it.

    Args:
        pattern: The server's pattern.

    Returns:
        str: The rewritten pattern, identical when nothing needed escaping.
    """
    marker_positions: set[int] = set()
    for start, end in forged_marker_spans(pattern):
        marker_positions.update(range(start, end))
    pieces: list[str] = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\" and index + 1 < len(pattern):
            following = pattern[index + 1]
            pieces.append(_ecma_escape(following) if _is_unsafe_in_pattern(following) else pattern[index : index + 2])
            index += 2
            continue
        in_marker = index in marker_positions and character.isalnum()
        pieces.append(_ecma_escape(character) if _is_unsafe_in_pattern(character) or in_marker else character)
        index += 1
    return "".join(pieces)


@dataclass(slots=True)
class _AliasTable:
    """The visible aliases chosen for one schema's unsafe identifiers.

    Attributes:
        taken: Every identifier the schema uses as written, and every alias
            already handed out, so a new alias never collides with either.
        forward: Original identifier to its alias.
    """

    taken: set[str] = field(default_factory=set[str])
    forward: dict[str, str] = field(default_factory=dict[str, str])

    def alias(self, identifier: str) -> str:
        """Return the identifier to advertise in place of ``identifier``.

        Args:
            identifier: The identifier as the server wrote it.

        Returns:
            str: ``identifier`` itself when it is safe to show, otherwise a
            visible alias unique within the schema.
        """
        existing = self.forward.get(identifier)
        if existing is not None:
            return existing
        if not identifier_needs_alias(identifier):
            return identifier
        candidate = escape_identifier(identifier)
        index = 1
        while candidate in self.taken:
            candidate = f"{escape_identifier(identifier)}{_ALIAS_SUFFIX.format(index=index)}"
            index += 1
        self.taken.add(candidate)
        self.forward[identifier] = candidate
        return candidate


@dataclass(frozen=True, slots=True)
class SanitizedSchema:
    """A schema safe to advertise, and how to undo its aliases.

    Attributes:
        schema: The rewritten schema.
        aliases: Each alias the schema advertises, mapped to the identifier the
            server wrote. Empty when nothing needed an alias.
    """

    schema: dict[str, Any]
    aliases: Mapping[str, str] = field(default_factory=dict[str, str])

    def restore_arguments(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Map every alias in a call's arguments back to what the server expects.

        Object keys and string values that are exactly an alias are replaced;
        everything else is passed through unchanged.

        Args:
            arguments: The arguments the model sent.

        Returns:
            dict[str, Any]: The arguments to deliver to the server.
        """
        if not self.aliases:
            return dict(arguments)
        restored = _map_instance(dict(arguments), lambda text: self.aliases.get(text, text))
        return restored if is_json_object(restored) else dict(arguments)


def _map_instance(value: object, rename: Callable[[str], str]) -> object:
    """Apply a string mapping to every object key and string in a JSON value.

    Args:
        value: The JSON value.
        rename: Maps one string to its replacement.

    Returns:
        object: A new value with every key and string mapped.
    """
    return map_json_strings(value, rename)


def _clean_annotation(value: object) -> object:
    """Clean every string in an annotation value, keys included.

    Args:
        value: The annotation's value.

    Returns:
        object: A new value whose strings are cleaned and bounded.
    """
    return _map_instance(value, lambda text: clean_untrusted_label(text, limit=SCHEMA_TEXT_LIMIT))


def _rewrite_reference(reference: str, table: _AliasTable) -> str:
    """Point a reference at the aliased name of what it named.

    Args:
        reference: A ``$ref`` or ``$dynamicRef`` value.
        table: The schema's aliases.

    Returns:
        str: The reference with each aliased pointer segment replaced.
    """
    base, hash_sign, pointer = reference.partition("#")
    if not hash_sign:
        return clean_untrusted_label(reference, limit=SCHEMA_TEXT_LIMIT)
    segments = pointer.split("/")
    rewritten: list[str] = []
    for segment in segments:
        name = segment.replace("~1", "/").replace("~0", "~")
        alias = table.alias(name) if segment else segment
        rewritten.append(alias.replace("~", "~0").replace("/", "~1") if alias != name else segment)
    return f"{clean_untrusted_label(base, limit=SCHEMA_TEXT_LIMIT)}#{'/'.join(rewritten)}"


def _walk(node: object, table: _AliasTable) -> object:
    """Rewrite one schema node.

    Args:
        node: The node; a boolean schema passes through.
        table: The schema's aliases, extended as unsafe identifiers are met.

    Returns:
        object: The rewritten node.
    """
    if is_json_array(node):
        return [_walk(member, table) for member in node]
    if not is_json_object(node):
        return node
    rewritten: dict[str, Any] = {}
    for key, value in node.items():
        if key in _NAME_MAP_KEYWORDS and is_json_object(value):
            rewritten[key] = {table.alias(name): _walk(member, table) for name, member in value.items()}
        elif key in _PATTERN_MAP_KEYWORDS and is_json_object(value):
            rewritten[key] = {sanitize_pattern(name): _walk(member, table) for name, member in value.items()}
        elif key in _SCHEMA_LIST_KEYWORDS or key in _SCHEMA_KEYWORDS:
            rewritten[key] = _walk(value, table)
        elif key in _NAME_LIST_KEYWORDS and is_json_array(value):
            rewritten[key] = [table.alias(name) if isinstance(name, str) else name for name in value]
        elif key == "dependentRequired" and is_json_object(value):
            rewritten[key] = {
                table.alias(name): [table.alias(item) if isinstance(item, str) else item for item in members]
                if is_json_array(members)
                else members
                for name, members in value.items()
            }
        elif key == "dependencies" and is_json_object(value):
            rewritten[key] = {
                table.alias(name): (
                    [table.alias(item) if isinstance(item, str) else item for item in members]
                    if is_json_array(members)
                    else _walk(members, table)
                )
                for name, members in value.items()
            }
        elif key in _VALUE_KEYWORDS:
            rewritten[key] = _map_instance(value, table.alias)
        elif key in _VALUE_LIST_KEYWORDS and is_json_array(value):
            rewritten[key] = [_map_instance(member, table.alias) for member in value]
        elif key in _REFERENCE_KEYWORDS and isinstance(value, str):
            rewritten[key] = _rewrite_reference(value, table)
        elif key in _PATTERN_KEYWORDS and isinstance(value, str):
            rewritten[key] = sanitize_pattern(value)
        else:
            rewritten[clean_untrusted_label(key, limit=SCHEMA_TEXT_LIMIT)] = _clean_annotation(value)
    return rewritten


def _collect_identifiers(node: object, found: set[str]) -> None:
    """Gather every string the schema uses as an identifier or instance value.

    Args:
        node: The schema node.
        found: Receives the strings.
    """
    if is_json_array(node):
        for member in node:
            _collect_identifiers(member, found)
        return
    if not is_json_object(node):
        return
    for key, value in node.items():
        if key in _NAME_MAP_KEYWORDS | _PATTERN_MAP_KEYWORDS and is_json_object(value):
            found.update(value)
            for member in value.values():
                _collect_identifiers(member, found)
        elif key in _SCHEMA_LIST_KEYWORDS or key in _SCHEMA_KEYWORDS:
            _collect_identifiers(value, found)
        elif key in _VALUE_KEYWORDS | _VALUE_LIST_KEYWORDS | _NAME_LIST_KEYWORDS | {"dependentRequired", "dependencies"}:
            _collect_instance_strings(value, found)
            if key == "dependencies" and is_json_object(value):
                for member in value.values():
                    _collect_identifiers(member, found)


def _collect_instance_strings(value: object, found: set[str]) -> None:
    """Gather every key and string of a JSON value.

    Args:
        value: The value.
        found: Receives the strings.
    """

    def _record(text: str) -> str:
        """Remember one string and hand it back unchanged.

        Args:
            text: The string.

        Returns:
            str: ``text``.
        """
        found.add(text)
        return text

    _ = _map_instance(value, _record)


def sanitize_input_schema(schema: Mapping[str, Any]) -> SanitizedSchema:
    """Rewrite a server's argument schema so it is safe to show a model.

    Args:
        schema: The raw ``inputSchema`` the server published.

    Containers nested deeper than
    :data:`~intellicrack.bridges.json_schema.MAX_SCHEMA_NESTING` are replaced by
    the permissive empty schema first, so no published schema, however deep,
    exhausts the recursion limit while it is rewritten.

    Returns:
        SanitizedSchema: The rewritten schema and the aliases it introduced.
    """
    bounded, replaced = truncate_schema_nesting(dict(schema))
    if replaced:
        _logger.warning("mcp_input_schema_nesting_truncated", nodes=replaced, limit=MAX_SCHEMA_NESTING)
    table = _AliasTable()
    _collect_identifiers(bounded, table.taken)
    rewritten = _walk(bounded, table)
    return SanitizedSchema(
        schema=rewritten if is_json_object(rewritten) else {},
        aliases={alias: original for original, alias in table.forward.items()},
    )


__all__ = [
    "SCHEMA_TEXT_LIMIT",
    "SanitizedSchema",
    "sanitize_input_schema",
    "sanitize_pattern",
]
