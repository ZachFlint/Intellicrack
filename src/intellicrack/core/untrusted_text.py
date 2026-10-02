# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Making text that an external party wrote safe to put in front of a model.

Anything a third-party server returns -- a tool description, a result, an error message, a schema annotation -- is a prompt-injection
surface. Three things keep it from being read as instruction:

* Invisible characters are removed. Terminal escapes, bidirectional overrides, zero-width joiners, byte-order marks and the Unicode tag
  block can all hide or reorder what a reader sees, so every control and format code point goes, except newline and tab. The Unicode line
  and paragraph separators, and a carriage return, become ordinary newlines.
* Forged fence markers are defanged. Untrusted text is wrapped between :data:`UNTRUSTED_BLOCK_START` and :data:`UNTRUSTED_BLOCK_END`, so
  text that writes the closing marker itself could end its own block early. The match is made on a normalized reading of the text --
  compatibility-folded, case-folded, with common Cyrillic and Greek look-alikes mapped to Latin and any separators allowed between the
  words -- so ``<<<end untrusted mcp server text>>>``, a full-width copy, or one spelled with a Cyrillic capital IE (U+0415) is caught as surely as the
  exact marker.
* Prose is bounded and fenced; identifiers that must survive a round trip are escaped visibly instead, because changing a property name
  or an enumeration value silently would make every call that uses it fail.

This module imports nothing outside the standard library, so every layer can use it.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final


UNTRUSTED_BLOCK_START: Final[str] = "<<<UNTRUSTED_MCP_SERVER_TEXT>>>"
"""Opening fence around text an external server supplied."""

UNTRUSTED_BLOCK_END: Final[str] = "<<<END_UNTRUSTED_MCP_SERVER_TEXT>>>"
"""Closing fence around text an external server supplied."""

DEFANGED_FENCE: Final[str] = "[fence]"
"""What a forged fence marker inside untrusted prose is replaced with."""

DEFAULT_UNTRUSTED_LIMIT: Final[int] = 4096
"""Default bound applied to one piece of fenced text."""

DEFAULT_LABEL_LIMIT: Final[int] = 512
"""Default bound applied to a short label such as a name, title or media type."""

_TRUNCATION_NOTE: Final[str] = "\n... [Intellicrack truncated {omitted} more characters]"

_KEPT_CONTROLS: Final[frozenset[str]] = frozenset({"\n", "\t"})

_LINE_BREAKS: Final[dict[str, str]] = {"\r": "\n", "\u0085": "\n", "\u2028": "\n", "\u2029": "\n"}
"""Code points that end a line, each rewritten as a newline rather than dropped."""

_LOOKALIKES: Final[dict[str, str]] = {
    "\u0430": "a",
    "\u0435": "e",
    "\u0451": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0443": "y",
    "\u0445": "x",
    "\u0442": "t",
    "\u043c": "m",
    "\u043d": "h",
    "\u043a": "k",
    "\u0455": "s",
    "\u0456": "i",
    "\u0458": "j",
    "\u0501": "d",
    "\u0578": "n",
    "\u057d": "u",
    "\u03bf": "o",
    "\u03b5": "e",
    "\u03c4": "t",
    "\u03bd": "v",
    "\u03c5": "u",
    "\u03c1": "p",
    "\u03ba": "k",
    "\u03b7": "n",
    "\u0131": "i",
    "\u2039": "<",
    "\u203a": ">",
    "\u00ab": "<",
    "\u00bb": ">",
    "\u2329": "<",
    "\u232a": ">",
    "\u3008": "<",
    "\u3009": ">",
    "\u27e8": "<",
    "\u27e9": ">",
    "\u276e": "<",
    "\u276f": ">",
    "\u02c2": "<",
    "\u02c3": ">",
    "\u1438": "<",
    "\u1433": ">",
}
"""Characters that read as a Latin letter or an angle bracket but that compatibility folding leaves alone."""

_SEPARATOR: Final[str] = r"[^a-z0-9\n]{0,6}"

_FORGED_MARKER: Final[re.Pattern[str]] = re.compile(
    rf"[<>]*{_SEPARATOR}(?:end{_SEPARATOR})?untrusted{_SEPARATOR}mcp{_SEPARATOR}server{_SEPARATOR}text{_SEPARATOR}[<>]*",
)
"""A fence marker as it reads after normalization, whatever its case, spacing, width or brackets."""

_IDENTIFIER_ESCAPE: Final[str] = "\\u{{{code:04x}}}"
"""How a character an identifier may not carry is written in its visible alias."""

_MARKER_BRACKETS: Final[frozenset[str]] = frozenset({"<", ">"})


def strip_control_characters(text: str) -> str:
    r"""Drop every control, format and unassigned code point except newline and tab.

    Carriage returns, NEL and the Unicode line and paragraph separators end a
    line, so they become newlines instead of vanishing; a ``\r\n`` pair
    becomes one newline.

    Args:
        text: Text an external party supplied.

    Returns:
        str: The text with terminal escapes, bidirectional overrides,
        zero-width and byte-order marks, tag characters and every other
        invisible code point removed.
    """
    unified = text.replace("\r\n", "\n")
    kept: list[str] = []
    for character in unified:
        replacement = _LINE_BREAKS.get(character)
        if replacement is not None:
            kept.append(replacement)
        elif character in _KEPT_CONTROLS or unicodedata.category(character)[0] != "C":
            kept.append(character)
    return "".join(kept)


def _normalized_reading(text: str) -> tuple[str, list[int]]:
    """Fold text the way a reader would see it, remembering where each folded character came from.

    Args:
        text: The text to fold.

    Returns:
        tuple[str, list[int]]: The folded text, and for each of its characters
        the index of the original character it came from.
    """
    if text.isascii():
        return text.lower(), list(range(len(text)))
    folded: list[str] = []
    origins: list[int] = []
    for index, character in enumerate(text):
        reading = _LOOKALIKES.get(character)
        if reading is None:
            reading = "".join(_LOOKALIKES.get(part, part) for part in unicodedata.normalize("NFKC", character).casefold())
        for part in reading:
            folded.append(part)
            origins.append(index)
    return "".join(folded), origins


def forged_marker_spans(text: str) -> list[tuple[int, int]]:
    """Find every stretch of text that reads as a fence marker.

    Args:
        text: The text to search, already stripped of control characters.

    Returns:
        list[tuple[int, int]]: ``(start, end)`` index ranges into ``text``,
        in order and not overlapping.
    """
    folded, origins = _normalized_reading(text)
    spans: list[tuple[int, int]] = []
    for match in _FORGED_MARKER.finditer(folded):
        if match.end() == match.start():
            continue
        start = origins[match.start()]
        end = origins[match.end() - 1] + 1
        if spans and start < spans[-1][1]:
            spans[-1] = (spans[-1][0], max(end, spans[-1][1]))
        else:
            spans.append((start, end))
    return spans


def defang_fence_markers(text: str) -> str:
    """Replace everything that reads as a fence marker with :data:`DEFANGED_FENCE`.

    Args:
        text: The text to defang, already stripped of control characters.

    Returns:
        str: The text with no forged opening or closing marker left in it.
    """
    spans = forged_marker_spans(text)
    if not spans:
        return text
    pieces: list[str] = []
    cursor = 0
    for start, end in spans:
        pieces.extend((text[cursor:start], DEFANGED_FENCE))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _bounded(text: str, limit: int) -> str:
    """Truncate text past a limit, saying how much was cut.

    Args:
        text: The text to bound.
        limit: Longest run of text kept.

    Returns:
        str: The text, or its first ``limit`` characters and a truncation note.
    """
    if len(text) <= limit:
        return text
    return f"{text[:limit]}{_TRUNCATION_NOTE.format(omitted=len(text) - limit)}"


def clean_untrusted_label(text: str, *, limit: int = DEFAULT_LABEL_LIMIT) -> str:
    """Make a short piece of untrusted text safe to show, without fencing it.

    For names, titles, media types, URIs and schema annotations: text that
    sits inside a structure rather than running free in a prompt.

    Args:
        text: The text an external party supplied.
        limit: Longest run of text kept.

    Returns:
        str: The text with invisible characters removed, forged fence markers
        defanged, and length bounded.
    """
    return _bounded(defang_fence_markers(strip_control_characters(text)), limit)


def sanitize_untrusted_text(text: str, *, limit: int = DEFAULT_UNTRUSTED_LIMIT) -> str:
    """Bound and fence a piece of text an external party supplied.

    Args:
        text: The text.
        limit: Longest run of text kept before truncation.

    Returns:
        str: The cleaned text between :data:`UNTRUSTED_BLOCK_START` and
        :data:`UNTRUSTED_BLOCK_END`, with no forged marker inside.
    """
    return f"{UNTRUSTED_BLOCK_START}\n{clean_untrusted_label(text, limit=limit)}\n{UNTRUSTED_BLOCK_END}"


def identifier_needs_alias(text: str) -> bool:
    """Report whether an identifier carries something a model must not be shown.

    Args:
        text: A property name, enumeration value or other string that must
            reach the server unchanged.

    Returns:
        bool: ``True`` when it holds an invisible or line-breaking character,
        or text that reads as a fence marker.
    """
    return any(_unsafe_in_identifier(character) for character in text) or bool(forged_marker_spans(text))


def _unsafe_in_identifier(character: str) -> bool:
    """Report whether one character may not appear as itself in an identifier a model sees.

    Args:
        character: The character to judge.

    Returns:
        bool: ``True`` for a line break and for every control, format or
        unassigned code point except tab.
    """
    if character == "\t":
        return False
    return character == "\n" or character in _LINE_BREAKS or unicodedata.category(character)[0] == "C"


def escape_identifier(text: str) -> str:
    r"""Write an identifier with every unsafe character spelled out visibly.

    Invisible and line-breaking characters become ``\u{XXXX}``. Within a
    stretch that reads as a fence marker the angle brackets are spelled out
    the same way, or, for a marker written without brackets, every character
    of it, so the stretch no longer reads as a marker. The result is not
    guaranteed unique across identifiers, so a caller that maps it back keeps
    its own table.

    Args:
        text: The identifier.

    Returns:
        str: The visible alias, identical to ``text`` when nothing needed
        escaping.
    """
    marker_positions: set[int] = set()
    for start, end in forged_marker_spans(text):
        marker_positions.update(range(start, end))

    def _escaped(*, whole_marker: bool) -> str:
        """Spell out the unsafe characters, and either the brackets or all of each marker.

        Args:
            whole_marker: Whether every character of a marker is spelled out,
                rather than only its brackets.

        Returns:
            str: The escaped identifier.
        """
        pieces: list[str] = []
        for index, character in enumerate(text):
            in_marker = index in marker_positions
            bracket = _LOOKALIKES.get(character, unicodedata.normalize("NFKC", character)) in _MARKER_BRACKETS
            if _unsafe_in_identifier(character) or (in_marker and (whole_marker or bracket)):
                pieces.append(_IDENTIFIER_ESCAPE.format(code=ord(character)))
            else:
                pieces.append(character)
        return "".join(pieces)

    escaped = _escaped(whole_marker=False)
    return _escaped(whole_marker=True) if forged_marker_spans(escaped) else escaped


__all__ = [
    "DEFANGED_FENCE",
    "DEFAULT_LABEL_LIMIT",
    "DEFAULT_UNTRUSTED_LIMIT",
    "UNTRUSTED_BLOCK_END",
    "UNTRUSTED_BLOCK_START",
    "clean_untrusted_label",
    "defang_fence_markers",
    "escape_identifier",
    "forged_marker_spans",
    "identifier_needs_alias",
    "sanitize_untrusted_text",
    "strip_control_characters",
]
