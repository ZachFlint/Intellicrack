# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Filling in a resource template's URI, as RFC 6570 defines it.

A server describes a family of resources with a URI template such as ``file:///{path}`` or ``db://tables/{table}{?limit}``; the
operator supplies each variable and the result is the URI to read. Every expression RFC 6570 defines is supported, with each variable a
single string: simple ``{var}``, reserved ``{+var}``, fragment ``{#var}``, label ``{.var}``, path ``{/var}``, path-style parameter
``{;var}``, query ``{?var}`` and continuation ``{&var}``, with several comma-separated variables per expression and the ``:n`` prefix
modifier. A variable left undefined is left out, as the RFC says.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final
from urllib.parse import quote


if TYPE_CHECKING:
    from collections.abc import Mapping


_EXPRESSION: Final[re.Pattern[str]] = re.compile(r"\{([^{}]*)}")
_VARIABLE: Final[re.Pattern[str]] = re.compile(r"^([A-Za-z0-9_.%]+)(?::(\d{1,4}))?(\*)?$")
_RESERVED_SAFE: Final[str] = ":/?#[]@!$&'()*+,;="


@dataclass(frozen=True, slots=True)
class _Operator:
    """How one expression operator expands.

    Attributes:
        first: What the expansion starts with when anything is defined.
        separator: What goes between variables.
        named: Whether each value is written as ``name=value``.
        if_empty: What follows a name whose value is empty.
        reserved: Whether reserved characters pass through unencoded.
    """

    first: str
    separator: str
    named: bool
    if_empty: str
    reserved: bool


_OPERATORS: Final[dict[str, _Operator]] = {
    "": _Operator("", ",", named=False, if_empty="", reserved=False),
    "+": _Operator("", ",", named=False, if_empty="", reserved=True),
    "#": _Operator("#", ",", named=False, if_empty="", reserved=True),
    ".": _Operator(".", ".", named=False, if_empty="", reserved=False),
    "/": _Operator("/", "/", named=False, if_empty="", reserved=False),
    ";": _Operator(";", ";", named=True, if_empty="", reserved=False),
    "?": _Operator("?", "&", named=True, if_empty="=", reserved=False),
    "&": _Operator("&", "&", named=True, if_empty="=", reserved=False),
}


def _split(expression: str) -> tuple[_Operator, list[tuple[str, int | None]]]:
    """Split one expression into its operator and variables.

    Args:
        expression: The text between the braces.

    Returns:
        tuple[_Operator, list[tuple[str, int | None]]]: The operator, and each
        variable's name with its prefix length, if any.

    Raises:
        ValueError: If the expression is not one RFC 6570 defines.
    """
    key = expression[:1] if expression[:1] and expression[:1] in _OPERATORS else ""
    body = expression[len(key) :]
    variables: list[tuple[str, int | None]] = []
    for spec in body.split(","):
        match = _VARIABLE.match(spec)
        if match is None:
            message = f"URI template expression {{{expression}}} is not valid"
            raise ValueError(message)
        variables.append((match.group(1), int(match.group(2)) if match.group(2) else None))
    return _OPERATORS[key], variables


def template_variables(template: str) -> list[str]:
    """List the variables a template expects, in order, each once.

    An expression RFC 6570 does not define is refused with the
    :class:`ValueError` its parser raises.

    Args:
        template: The URI template.

    Returns:
        list[str]: The variable names.
    """
    names: list[str] = []
    for expression in _EXPRESSION.findall(template):
        _, variables = _split(expression)
        names.extend(name for name, _ in variables if name not in names)
    return names


def _encode(value: str, *, reserved: bool) -> str:
    """Percent-encode one value.

    Args:
        value: The value.
        reserved: Whether reserved characters pass through.

    Returns:
        str: The encoded value.
    """
    return quote(value, safe=_RESERVED_SAFE if reserved else "")


def expand_uri_template(template: str, values: Mapping[str, str]) -> str:
    """Fill in a URI template.

    An expression RFC 6570 does not define is refused with the
    :class:`ValueError` its parser raises.

    Args:
        template: The URI template.
        values: A value for each variable; one that is missing is left out.

    Returns:
        str: The URI.
    """

    def _expand(match: re.Match[str]) -> str:
        """Expand one expression.

        Args:
            match: The expression, braces included.

        Returns:
            str: Its expansion.
        """
        operator, variables = _split(match.group(1))
        pieces: list[str] = []
        for name, prefix in variables:
            value = values.get(name)
            if value is None:
                continue
            encoded = _encode(value[:prefix] if prefix is not None else value, reserved=operator.reserved)
            if operator.named:
                pieces.append(f"{name}{f'={encoded}' if encoded else operator.if_empty}")
            else:
                pieces.append(encoded)
        return operator.first + operator.separator.join(pieces) if pieces else ""

    return _EXPRESSION.sub(_expand, template)
