# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""JSON Schema validation for structured tool output.

A server that publishes an ``outputSchema`` has made a promise about what its
tools return. This module checks the promise, so a result that quietly does
not match is reported as a protocol violation rather than handed to the model
as if it were what the tool advertised.

The checker covers the JSON Schema 2020-12 assertion vocabulary that tool
output schemas actually use: types, enumerations, object and array shape,
numeric and string bounds, and the boolean combinators. ``$ref`` is resolved
first through :func:`intellicrack.bridges.json_schema.inline_refs`, which is
the same expansion the provider boundary applies, so a schema validates here
exactly as it is understood everywhere else in Intellicrack.

Annotation-only keywords -- ``title``, ``description``, ``default``,
``examples``, ``format``, ``$comment`` -- assert nothing and are skipped, which
is what the specification calls for.
"""

from __future__ import annotations

import functools
import itertools
import math
import re
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

import regex

from intellicrack.bridges.json_schema import inline_refs
from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence


_logger = get_logger(__name__)


MAX_VALIDATION_DEPTH: Final[int] = 64
"""Deepest nesting the checker descends before giving up on a branch."""

MAX_PATTERN_CHARS: Final[int] = 1024
"""Longest ``pattern`` the checker will compile at all."""

PATTERN_MATCH_TIMEOUT_S: Final[float] = 0.05
"""Longest one schema pattern may run against one string before the assertion is abandoned."""

PATTERN_VALIDATION_BUDGET_S: Final[float] = 0.25
"""Longest all schema patterns together may run during one :func:`validate_against_schema` call."""

MAX_BOUNDED_REPETITION_WAYS: Final[int] = 10_000
"""Most ways a bounded repetition of a variable-width group may split its input before it is refused."""

MAX_OVERLAPPING_UNBOUNDED_RUN: Final[int] = 2
"""Most unbounded repetitions over overlapping characters one sequence may chain before it is refused."""

_SAMPLE_ALPHABET: Final[str] = "".join(chr(code) for code in (*range(32, 127), 0x09, 0x0A, 0x0D, 0xA0, 0xE9, 0x436, 0x4E2D, 0x1F600))
"""Characters used to decide whether two single-character atoms can match the same text."""

_BRACE_QUANTIFIER: Final[re.Pattern[str]] = re.compile(r"\{(\d*)(?:(,)(\d*))?\}")

_ZERO_WIDTH_ESCAPES: Final[frozenset[str]] = frozenset("bBAZzG")


@dataclass(frozen=True, slots=True)
class _Atom:
    """One parsed regular-expression atom.

    Attributes:
        source: The atom's text in the expression.
        alternatives: For a group, the sequences its alternation chooses
            between; empty for any other atom.
        zero_width: Whether the atom consumes no input (an anchor, a word
            boundary or a lookaround).
    """

    source: str
    alternatives: tuple[tuple[_Item, ...], ...] = ()
    zero_width: bool = False

    @property
    def is_group(self) -> bool:
        """Whether this atom is a group.

        Returns:
            bool: ``True`` for a group of any kind.
        """
        return bool(self.alternatives)


@dataclass(frozen=True, slots=True)
class _Item:
    """One atom and the repetition applied to it.

    Attributes:
        atom: The repeated atom.
        minimum: Fewest repetitions.
        maximum: Most repetitions, or ``None`` when unbounded.
    """

    atom: _Atom
    minimum: int
    maximum: int | None


class _PatternParser:
    """A single-pass structural parser for schema regular expressions.

    It recovers only what the backtracking analysis needs -- groups,
    alternation, repetition and atom boundaries -- and treats anything it
    does not recognise as a literal. Compiling the expression, not this
    parser, decides whether it is valid.
    """

    def __init__(self, expression: str) -> None:
        """Start parsing one expression.

        Args:
            expression: The regular expression source.
        """
        self._text = expression
        self._index = 0

    def parse(self) -> tuple[tuple[_Item, ...], ...]:
        """Parse the whole expression.

        Returns:
            tuple[tuple[_Item, ...], ...]: The top-level alternatives.
        """
        alternatives = self._alternation()
        while self._index < len(self._text):
            self._index += 1
            alternatives = (*alternatives, *self._alternation())
        return alternatives

    def _peek(self, offset: int = 0) -> str:
        """Read one character ahead without consuming it.

        Args:
            offset: How far past the current position to look.

        Returns:
            str: The character, or ``""`` past the end.
        """
        position = self._index + offset
        return self._text[position] if position < len(self._text) else ""

    def _alternation(self) -> tuple[tuple[_Item, ...], ...]:
        """Parse alternatives up to a closing parenthesis or the end.

        Returns:
            tuple[tuple[_Item, ...], ...]: One sequence per alternative.
        """
        sequences = [self._sequence()]
        while self._peek() == "|":
            self._index += 1
            sequences.append(self._sequence())
        return tuple(sequences)

    def _sequence(self) -> tuple[_Item, ...]:
        """Parse one alternative: atoms and their repetitions.

        Returns:
            tuple[_Item, ...]: The alternative's items, in order.
        """
        items: list[_Item] = []
        while self._index < len(self._text) and self._peek() not in "|)":
            atom = self._atom()
            if atom is None:
                continue
            minimum, maximum = self._quantifier()
            items.append(_Item(atom=atom, minimum=minimum, maximum=maximum))
        return tuple(items)

    def _atom(self) -> _Atom | None:
        """Parse one atom.

        Returns:
            _Atom | None: The atom, or ``None`` for text that matches nothing
            by itself, such as an inline flag group or a comment.
        """
        start = self._index
        character = self._peek()
        if character == "(":
            return self._group()
        if character == "[":
            self._skip_class()
            return _Atom(source=self._text[start : self._index])
        if character == "\\":
            return self._escape()
        self._index += 1
        return _Atom(source=character, zero_width=character in "^$")

    def _group(self) -> _Atom | None:
        """Parse a parenthesised group of any kind.

        Returns:
            _Atom | None: The group, or ``None`` for a comment or an inline
            flag setting.
        """
        start = self._index
        self._index += 1
        zero_width = False
        if self._peek() == "?":
            self._index += 1
            marker = self._peek()
            if marker in ":>|":
                self._index += 1
            elif marker in "=!":
                zero_width = True
                self._index += 1
            elif marker == "<" and self._peek(1) in "=!":
                zero_width = True
                self._index += 2
            elif marker in "P<'":
                closing = ">" if marker != "'" else "'"
                end = self._text.find(closing, self._index + 1)
                self._index = len(self._text) if end == -1 else end + 1
            elif marker == "#":
                end = self._text.find(")", self._index)
                self._index = len(self._text) if end == -1 else end + 1
                return None
            else:
                while self._index < len(self._text) and self._peek() not in ":)":
                    self._index += 1
                if self._peek() == ")":
                    self._index += 1
                    return None
                self._index += 1
        alternatives = self._alternation()
        if self._peek() == ")":
            self._index += 1
        return _Atom(source=self._text[start : self._index], alternatives=alternatives or ((),), zero_width=zero_width)

    def _skip_class(self) -> None:
        """Advance past one bracketed character class."""
        self._index += 1
        if self._peek() == "^":
            self._index += 1
        if self._peek() == "]":
            self._index += 1
        while self._index < len(self._text):
            character = self._peek()
            self._index += 2 if character == "\\" else 1
            if character == "]":
                return

    def _escape(self) -> _Atom:
        """Parse one backslash escape.

        Returns:
            _Atom: The escaped atom.
        """
        start = self._index
        self._index += 1
        letter = self._peek()
        self._index += 1
        if letter in "pPNx" and self._peek() == "{":
            end = self._text.find("}", self._index)
            self._index = len(self._text) if end == -1 else end + 1
        elif letter == "x":
            self._index = min(len(self._text), self._index + 2)
        elif letter == "u":
            self._index = min(len(self._text), self._index + 4)
        elif letter == "U":
            self._index = min(len(self._text), self._index + 8)
        return _Atom(source=self._text[start : self._index], zero_width=letter in _ZERO_WIDTH_ESCAPES)

    def _quantifier(self) -> tuple[int, int | None]:
        """Parse the repetition following an atom, if any.

        Returns:
            tuple[int, int | None]: The fewest and most repetitions, ``(1, 1)``
            when the atom is not repeated.
        """
        character = self._peek()
        bounds: tuple[int, int | None]
        if character == "*":
            bounds = (0, None)
        elif character == "+":
            bounds = (1, None)
        elif character == "?":
            bounds = (0, 1)
        elif character == "{" and (match := _BRACE_QUANTIFIER.match(self._text, self._index)) and (match.group(1) or match.group(3)):
            low = int(match.group(1) or "0")
            upper = int(match.group(3)) if match.group(3) else None
            bounds = (low, low) if match.group(2) is None else (low, upper)
            self._index = match.end() - 1
        else:
            return 1, 1
        self._index += 1
        if self._peek() in "?+":
            self._index += 1
        return bounds


def _varies(alternatives: tuple[tuple[_Item, ...], ...]) -> bool:
    """Report whether a group body can match inputs of different shapes.

    Args:
        alternatives: The group's alternatives.

    Returns:
        bool: ``True`` when the body alternates or repeats anything a
        variable number of times.
    """
    if len(alternatives) > 1:
        return True
    return any(
        item.minimum != item.maximum or (item.atom.is_group and _varies(item.atom.alternatives))
        for sequence in alternatives
        for item in sequence
    )


def _unbounded(alternatives: tuple[tuple[_Item, ...], ...]) -> bool:
    """Report whether a group body repeats anything without an upper bound.

    Args:
        alternatives: The group's alternatives.

    Returns:
        bool: ``True`` when some repetition inside is unbounded.
    """
    return any(
        item.maximum is None or (item.atom.is_group and _unbounded(item.atom.alternatives))
        for sequence in alternatives
        for item in sequence
    )


def _capped_power(base: int, exponent: int, ceiling: int) -> int:
    """Raise a count to a power, stopping once it passes a ceiling.

    Args:
        base: The count.
        exponent: The power, which may be very large.
        ceiling: The value past which the exact result does not matter.

    Returns:
        int: ``base ** exponent``, or ``ceiling`` when that would exceed it.
    """
    if base <= 1:
        return base if exponent > 0 else 1
    result = 1
    for _ in range(exponent):
        result *= base
        if result >= ceiling:
            return ceiling
    return result


def _ways(alternatives: tuple[tuple[_Item, ...], ...]) -> int:
    """Estimate how many ways a bounded group body can split its input.

    The count is capped just past :data:`MAX_BOUNDED_REPETITION_WAYS`, which
    is all the caller needs to know.

    Args:
        alternatives: The group's alternatives; every repetition inside is
            bounded.

    Returns:
        int: The estimate, at most one past the refusal threshold.
    """
    ceiling = MAX_BOUNDED_REPETITION_WAYS + 1
    total = 0
    for sequence in alternatives:
        product = 1
        for item in sequence:
            maximum = item.maximum if item.maximum is not None else ceiling
            span = maximum - item.minimum + 1
            inner = _ways(item.atom.alternatives) if item.atom.is_group else 1
            product = min(ceiling, product * span * _capped_power(inner, maximum, ceiling))
        total = min(ceiling, total + product)
    return total


@functools.lru_cache(maxsize=4096)
def _matchable_characters(source: str) -> frozenset[str]:
    """Sample the characters one single-character atom can match.

    Args:
        source: The atom's text: a literal, an escape, ``.`` or a class.

    Returns:
        frozenset[str]: The sample characters it matches; every sample when
        it cannot be compiled on its own.
    """
    if len(source) == 1 and source != ".":
        return frozenset(source)
    try:
        compiled = regex.compile(source)
    except regex.error:
        return frozenset(_SAMPLE_ALPHABET)
    return frozenset(character for character in _SAMPLE_ALPHABET if compiled.fullmatch(character) is not None)


def _first_characters(atom: _Atom) -> frozenset[str]:
    """Sample the characters an atom's match can start with.

    Args:
        atom: The atom.

    Returns:
        frozenset[str]: The sample characters; every sample for a group,
        which is the conservative answer.
    """
    if atom.is_group:
        return frozenset(_SAMPLE_ALPHABET)
    return _matchable_characters(atom.source)


def _sequence_hazard(sequence: tuple[_Item, ...]) -> str | None:
    """Find the first backtracking hazard in one sequence and its groups.

    Args:
        sequence: The sequence to check.

    Returns:
        str | None: Why the sequence is refused, or ``None`` when it is safe.
    """
    run = 0
    previous: frozenset[str] | None = None
    for item in sequence:
        atom = item.atom
        if atom.is_group:
            if (hazard := _group_hazard(item)) is not None:
                return hazard
            for inner in atom.alternatives:
                if (hazard := _sequence_hazard(inner)) is not None:
                    return hazard
        if atom.zero_width:
            continue
        characters = _first_characters(atom)
        if item.maximum is None:
            run = run + 1 if previous is not None and characters & previous else 1
            previous = characters
            if run > MAX_OVERLAPPING_UNBOUNDED_RUN:
                return f"{run} adjacent unbounded repetitions over overlapping characters"
        elif item.minimum > 0 and previous is not None and not characters & previous:
            run = 0
            previous = None
    return None


def _group_hazard(item: _Item) -> str | None:
    """Judge one repeated group for nested-repetition backtracking.

    Args:
        item: A group atom and its repetition.

    Returns:
        str | None: Why the repetition is refused, or ``None`` when it is
        safe.
    """
    alternatives = item.atom.alternatives
    repeats = item.maximum is None or item.maximum > 1
    if not repeats or item.atom.zero_width or not _varies(alternatives):
        return None
    if item.maximum is None:
        return "an unbounded repetition of a variable-width group"
    if _unbounded(alternatives):
        return "a repeated group containing an unbounded repetition"
    ways = _ways(alternatives)
    if _capped_power(ways, item.maximum, MAX_BOUNDED_REPETITION_WAYS + 1) > MAX_BOUNDED_REPETITION_WAYS:
        return f"a group repeated {item.maximum} times that can split its input {ways} ways each time"
    return None


def pattern_hazard(expression: str) -> str | None:
    """Explain why a schema pattern could backtrack catastrophically.

    Three shapes are refused. An unbounded repetition of a group whose body
    can match more than one way, such as ``(a+)+`` or ``(a{1,1000})+``. A
    repetition of any count of a group that itself repeats without bound,
    such as ``(a+){2,40}`` or ``(.*a){12}``. And a bounded repetition whose
    ways of splitting the input multiply past
    :data:`MAX_BOUNDED_REPETITION_WAYS`, while an ordinary IPv4 pattern,
    three ways repeated three times, is left alone. Separately, more than
    :data:`MAX_OVERLAPPING_UNBOUNDED_RUN` unbounded repetitions in a row over
    characters they can share, such as ``a*a*a*a*a*b``, backtrack
    polynomially in the input length and are refused.

    Args:
        expression: The regular expression source.

    Returns:
        str | None: Why the pattern is refused, or ``None`` when it is safe.
    """
    for sequence in _PatternParser(expression).parse():
        if (hazard := _sequence_hazard(sequence)) is not None:
            return hazard
    return None


@functools.lru_cache(maxsize=512)
def compile_schema_pattern(expression: str) -> regex.Pattern[str] | None:
    """Compile a schema-supplied regular expression, or refuse it.

    The ``pattern`` and ``patternProperties`` keywords of an output schema
    are written by the server, and so is the text they are matched against.
    A backtracking engine lets those two together hang the client:
    ``(a+)+$`` against thirty characters does not finish. A pattern whose
    shape invites that, per :func:`pattern_hazard`, is refused outright, and
    every pattern that is compiled is matched through :func:`search_pattern`
    under a hard time limit, so a shape the analysis misses still cannot
    hold the event loop.

    A pattern this function refuses is simply not checked. That loses one
    assertion about a server's own output, which is a far smaller cost than
    a frozen event loop.

    Args:
        expression: The regular expression from the schema.

    Returns:
        regex.Pattern[str] | None: The compiled pattern, or ``None`` when it
        is too long, will not compile, or has a catastrophic shape.
    """
    if len(expression) > MAX_PATTERN_CHARS:
        _logger.warning("json_schema_pattern_too_long", length=len(expression), limit=MAX_PATTERN_CHARS)
        return None
    if (hazard := pattern_hazard(expression)) is not None:
        _logger.warning("json_schema_pattern_refused", pattern=expression[:128], reason=hazard)
        return None
    try:
        return regex.compile(expression)
    except regex.error:
        _logger.debug("json_schema_pattern_invalid", pattern=expression[:128])
        return None


_pattern_deadline: ContextVar[float | None] = ContextVar("_pattern_deadline", default=None)
"""Monotonic time after which no further pattern is run in the current validation."""


def search_pattern(compiled: regex.Pattern[str], text: str) -> bool | None:
    """Search one string with a schema pattern under a hard time limit.

    The ``regex`` engine checks its timeout while it backtracks and releases
    the GIL while it matches, so an expensive pattern costs at most
    :data:`PATTERN_MATCH_TIMEOUT_S`, and all patterns in one validation
    together at most :data:`PATTERN_VALIDATION_BUDGET_S`.

    Args:
        compiled: The pattern, from :func:`compile_schema_pattern`.
        text: The string to search.

    Returns:
        bool | None: Whether the pattern matches, or ``None`` when it could
        not be decided within the time limit.
    """
    limit = PATTERN_MATCH_TIMEOUT_S
    deadline = _pattern_deadline.get()
    if deadline is not None:
        limit = min(limit, deadline - time.monotonic())
        if limit <= 0:
            _logger.debug("json_schema_pattern_budget_exhausted", pattern=compiled.pattern[:128])
            return None
    try:
        return compiled.search(text, timeout=limit) is not None
    except TimeoutError:
        _logger.warning("json_schema_pattern_timed_out", pattern=compiled.pattern[:128], length=len(text), limit_s=limit)
        return None


MAX_VIOLATIONS: Final[int] = 32
"""Most violations collected before reporting stops, so one badly-shaped result cannot produce an unbounded error message."""

_TYPE_CHECKS: Final[dict[str, str]] = {
    "null": "null",
    "boolean": "a boolean",
    "object": "an object",
    "array": "an array",
    "number": "a number",
    "integer": "an integer",
    "string": "a string",
}

_NUMERIC_EPSILON: Final[float] = 1e-9

_ENUM_PREVIEW_VALUES: Final[int] = 8
"""How many allowed values an enumeration violation names before eliding."""


@dataclass(frozen=True, slots=True)
class SchemaViolation:
    """One way an instance failed its schema.

    Attributes:
        path: JSON-pointer-like location of the offending value, e.g.
            ``$.items[2].name``.
        message: What the schema required and what was found instead.
    """

    path: str
    message: str

    def __str__(self) -> str:
        """Render the violation as one readable line.

        Returns:
            str: ``<path>: <message>``.
        """
        return f"{self.path}: {self.message}"


def _json_type_of(value: object) -> str:
    """Name the JSON type of a decoded value.

    Args:
        value: The value to classify.

    Returns:
        str: One of the JSON Schema type names, or ``"unknown"`` for a value
        that did not come from JSON.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if is_json_array(value):
        return "array"
    return "object" if is_json_object(value) else "unknown"


def _matches_type(value: object, declared: str) -> bool:
    """Check a value against one declared JSON Schema type.

    Args:
        value: The value to check.
        declared: The schema's type name.

    Returns:
        bool: ``True`` when the value satisfies the type. An integral float
        satisfies ``integer``, which is what the specification requires.
    """
    actual = _json_type_of(value)
    if declared == "number":
        return actual in {"integer", "number"}
    if declared == "integer":
        return actual == "integer" or (actual == "number" and isinstance(value, float) and value.is_integer())
    return actual == declared


def _check_type(value: object, schema: Mapping[str, Any], path: str) -> Iterator[SchemaViolation]:
    """Check the ``type`` keyword.

    A ``null`` value satisfies any type on a node marked ``nullable: true``,
    which is how OpenAPI 3.0 schemas, and Gemini's, spell a nullable type.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.

    Yields:
        SchemaViolation: One violation when the type does not match.
    """
    declared = schema.get("type")
    if declared is None or (value is None and schema.get("nullable") is True):
        return
    names = [declared] if isinstance(declared, str) else [item for item in declared if isinstance(item, str)]
    if not names or any(_matches_type(value, name) for name in names):
        return
    expected = " or ".join(_TYPE_CHECKS.get(name, name) for name in names)
    yield SchemaViolation(path=path, message=f"expected {expected}, found {_TYPE_CHECKS.get(_json_type_of(value), 'an unsupported value')}")


def _json_equal(left: object, right: object) -> bool:
    """Compare two decoded JSON values the way JSON Schema does.

    Python's ``==`` makes ``True == 1`` and ``False == 0``, but JSON booleans
    and numbers are different types. Numbers compare by value, so ``1`` and
    ``1.0`` are equal; arrays compare element by element and objects key by
    key, each with the same rule.

    Args:
        left: One value.
        right: The other value.

    Returns:
        bool: ``True`` when the two are the same JSON value.
    """
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right
    if isinstance(left, int | float) and isinstance(right, int | float):
        return left == right
    if is_json_array(left) and is_json_array(right):
        return len(left) == len(right) and all(itertools.starmap(_json_equal, zip(left, right, strict=True)))
    if is_json_object(left) and is_json_object(right):
        return left.keys() == right.keys() and all(_json_equal(item, right[key]) for key, item in left.items())
    return type(left) is type(right) and left == right


def _check_enumeration(value: object, schema: Mapping[str, Any], path: str) -> Iterator[SchemaViolation]:
    """Check the ``enum`` and ``const`` keywords.

    A ``null`` value is accepted by a node marked ``nullable: true``, the
    OpenAPI spelling of a type union with ``null``.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.

    Yields:
        SchemaViolation: One violation per failed keyword.
    """
    if value is None and schema.get("nullable") is True:
        return
    if "const" in schema and not _json_equal(value, schema["const"]):
        yield SchemaViolation(path=path, message=f"must equal {schema['const']!r}")
    allowed = schema.get("enum")
    if is_json_array(allowed) and not any(_json_equal(value, item) for item in allowed):
        rendered = ", ".join(repr(item) for item in allowed[:_ENUM_PREVIEW_VALUES])
        suffix = ", ..." if len(allowed) > _ENUM_PREVIEW_VALUES else ""
        yield SchemaViolation(path=path, message=f"must be one of [{rendered}{suffix}]")


def _check_number(value: object, schema: Mapping[str, Any], path: str) -> Iterator[SchemaViolation]:
    """Check the numeric bound keywords.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.

    Yields:
        SchemaViolation: One violation per failed bound.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return
    number = float(value)
    bounds: tuple[tuple[str, str], ...] = (
        ("minimum", "at least"),
        ("maximum", "at most"),
        ("exclusiveMinimum", "greater than"),
        ("exclusiveMaximum", "less than"),
    )
    for keyword, phrasing in bounds:
        limit = schema.get(keyword)
        if isinstance(limit, bool) or not isinstance(limit, int | float):
            continue
        boundary = float(limit)
        failed = (
            (keyword == "minimum" and number < boundary)
            or (keyword == "maximum" and number > boundary)
            or (keyword == "exclusiveMinimum" and number <= boundary)
            or (keyword == "exclusiveMaximum" and number >= boundary)
        )
        if failed:
            yield SchemaViolation(path=path, message=f"must be {phrasing} {limit}")

    divisor = schema.get("multipleOf")
    if not isinstance(divisor, bool) and isinstance(divisor, int | float) and float(divisor) > 0:
        remainder = math.fmod(number, float(divisor))
        if min(abs(remainder), abs(abs(remainder) - abs(float(divisor)))) > _NUMERIC_EPSILON:
            yield SchemaViolation(path=path, message=f"must be a multiple of {divisor}")


def _check_string(value: object, schema: Mapping[str, Any], path: str) -> Iterator[SchemaViolation]:
    """Check the string bound and pattern keywords.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.

    Yields:
        SchemaViolation: One violation per failed keyword.
    """
    if not isinstance(value, str):
        return
    minimum = schema.get("minLength")
    if isinstance(minimum, int) and not isinstance(minimum, bool) and len(value) < minimum:
        yield SchemaViolation(path=path, message=f"must be at least {minimum} characters")
    maximum = schema.get("maxLength")
    if isinstance(maximum, int) and not isinstance(maximum, bool) and len(value) > maximum:
        yield SchemaViolation(path=path, message=f"must be at most {maximum} characters")
    pattern = schema.get("pattern")
    if isinstance(pattern, str):
        compiled = compile_schema_pattern(pattern)
        if compiled is not None and search_pattern(compiled, value) is False:
            yield SchemaViolation(path=path, message=f"must match {pattern!r}")


def _check_array(value: object, schema: Mapping[str, Any], path: str, depth: int) -> Iterator[SchemaViolation]:
    """Check the array shape keywords.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.
        depth: Remaining recursion budget.

    Yields:
        SchemaViolation: One violation per failed keyword or element.
    """
    if not is_json_array(value):
        return
    minimum = schema.get("minItems")
    if isinstance(minimum, int) and not isinstance(minimum, bool) and len(value) < minimum:
        yield SchemaViolation(path=path, message=f"must have at least {minimum} items")
    maximum = schema.get("maxItems")
    if isinstance(maximum, int) and not isinstance(maximum, bool) and len(value) > maximum:
        yield SchemaViolation(path=path, message=f"must have at most {maximum} items")
    if schema.get("uniqueItems") is True and _has_duplicates(value):
        yield SchemaViolation(path=path, message="items must be unique")

    prefix = schema.get("prefixItems")
    prefix_schemas = list(prefix) if is_json_array(prefix) else []
    for index, element in enumerate(value):
        if index < len(prefix_schemas):
            yield from _validate(element, prefix_schemas[index], f"{path}[{index}]", depth - 1)
            continue
        items = schema.get("items")
        if items is not None:
            yield from _validate(element, items, f"{path}[{index}]", depth - 1)


def _has_duplicates(items: Sequence[object]) -> bool:
    """Report whether a JSON array holds two equal elements.

    Equality is JSON equality, so ``1`` and ``true`` are distinct and
    unhashable values are compared directly rather than through a set.

    Args:
        items: The array elements.

    Returns:
        bool: ``True`` when any two elements are equal.
    """
    seen: list[object] = []
    for item in items:
        if any(_json_equal(item, existing) for existing in seen):
            return True
        seen.append(item)
    return False


def _check_object(value: object, schema: Mapping[str, Any], path: str, depth: int) -> Iterator[SchemaViolation]:
    """Check the object shape keywords.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.
        depth: Remaining recursion budget.

    Yields:
        SchemaViolation: One violation per failed keyword or property.
    """
    if not is_json_object(value):
        return
    required = schema.get("required")
    if is_json_array(required):
        for name in required:
            if isinstance(name, str) and name not in value:
                yield SchemaViolation(path=path, message=f"missing required property {name!r}")

    minimum = schema.get("minProperties")
    if isinstance(minimum, int) and not isinstance(minimum, bool) and len(value) < minimum:
        yield SchemaViolation(path=path, message=f"must have at least {minimum} properties")
    maximum = schema.get("maxProperties")
    if isinstance(maximum, int) and not isinstance(maximum, bool) and len(value) > maximum:
        yield SchemaViolation(path=path, message=f"must have at most {maximum} properties")

    properties = schema.get("properties")
    declared = properties if is_json_object(properties) else {}
    patterns = schema.get("patternProperties")
    declared_patterns = patterns if is_json_object(patterns) else {}

    for name, item in value.items():
        matched = False
        if name in declared:
            matched = True
            yield from _validate(item, declared[name], f"{path}.{name}", depth - 1)
        for expression, sub_schema in declared_patterns.items():
            decided = _pattern_matches(expression, name)
            if decided is None:
                matched = True
            elif decided:
                matched = True
                yield from _validate(item, sub_schema, f"{path}.{name}", depth - 1)
        if matched:
            continue
        additional = schema.get("additionalProperties")
        if additional is False:
            yield SchemaViolation(path=path, message=f"unexpected property {name!r}")
        elif additional is not None and additional is not True:
            yield from _validate(item, additional, f"{path}.{name}", depth - 1)


def _pattern_matches(expression: str, name: str) -> bool | None:
    """Test one ``patternProperties`` key against a property name.

    Args:
        expression: The regular expression from the schema.
        name: The property name.

    Returns:
        bool | None: Whether the expression matches, or ``None`` when that
        cannot be decided because the expression will not compile, was
        refused as unsafe to run, or ran out of time. An undecided name is
        treated as covered, so it is neither validated against the pattern's
        subschema nor reported as an unexpected property.
    """
    compiled = compile_schema_pattern(expression)
    return None if compiled is None else search_pattern(compiled, name)


def _check_combinators(value: object, schema: Mapping[str, Any], path: str, depth: int) -> Iterator[SchemaViolation]:
    """Check the boolean combinator keywords.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.
        depth: Remaining recursion budget.

    Yields:
        SchemaViolation: One violation per failed combinator.
    """
    all_of = schema.get("allOf")
    if is_json_array(all_of):
        for branch in all_of:
            yield from _validate(value, branch, path, depth - 1)

    any_of = schema.get("anyOf")
    if is_json_array(any_of) and any_of and all(_validate(value, branch, path, depth - 1) for branch in any_of):
        yield SchemaViolation(path=path, message="does not match any accepted shape")

    one_of = schema.get("oneOf")
    if is_json_array(one_of) and one_of:
        matches = sum(not _validate(value, branch, path, depth - 1) for branch in one_of)
        if matches != 1:
            yield SchemaViolation(path=path, message=f"must match exactly one accepted shape, matched {matches}")

    negated = schema.get("not")
    if negated is not None and not _validate(value, negated, path, depth - 1):
        yield SchemaViolation(path=path, message="matches a shape the schema forbids")

    condition = schema.get("if")
    if condition is not None:
        branch = schema.get("else") if _validate(value, condition, path, depth - 1) else schema.get("then")
        if branch is not None:
            yield from _validate(value, branch, path, depth - 1)


def _validate(value: object, schema: object, path: str, depth: int) -> list[SchemaViolation]:
    """Validate one value against one schema node.

    Args:
        value: The value to check.
        schema: The schema node, which may be a boolean schema.
        path: Location of ``value``.
        depth: Remaining recursion budget.

    Returns:
        list[SchemaViolation]: Every violation found, capped at
        :data:`MAX_VIOLATIONS`.
    """
    if schema is True or schema is None:
        return []
    if schema is False:
        return [SchemaViolation(path=path, message="no value is accepted here")]
    if not is_json_object(schema):
        return []
    if depth <= 0:
        _logger.warning("json_schema_validation_depth_exceeded", path=path)
        return []

    violations: list[SchemaViolation] = []
    for check in (
        _check_type(value, schema, path),
        _check_enumeration(value, schema, path),
        _check_number(value, schema, path),
        _check_string(value, schema, path),
        _check_array(value, schema, path, depth),
        _check_object(value, schema, path, depth),
        _check_combinators(value, schema, path, depth),
    ):
        for violation in check:
            violations.append(violation)
            if len(violations) >= MAX_VIOLATIONS:
                return violations
    return violations


def validate_against_schema(value: object, schema: Mapping[str, Any]) -> list[SchemaViolation]:
    """Validate a decoded JSON value against a JSON Schema.

    Local ``$ref`` pointers are expanded first, so a schema built from
    ``$defs`` validates as written. Schema patterns share a
    :data:`PATTERN_VALIDATION_BUDGET_S` time budget for the whole call.

    Args:
        value: The decoded JSON value to check.
        schema: The schema to check it against.

    Returns:
        list[SchemaViolation]: Every violation found, empty when the value
        conforms.
    """
    expanded = inline_refs(dict(schema))
    token = _pattern_deadline.set(time.monotonic() + PATTERN_VALIDATION_BUDGET_S)
    try:
        return _validate(value, expanded, "$", MAX_VALIDATION_DEPTH)
    finally:
        _pattern_deadline.reset(token)
