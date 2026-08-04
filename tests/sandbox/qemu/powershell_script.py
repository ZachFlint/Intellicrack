# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Evaluation of the declarations the generated Windows agent script makes.

The host writes ``agent.ps1`` before the guest has assigned the FAT volume a
drive letter and before it knows where that guest installed Windows, so every
directory the script uses is *derived* inside the guest: from ``$PSScriptRoot``
for the share, and from ``%SystemDrive%``/``%SystemRoot%`` for the volume the
sample writes to. A model of the guest that hard-codes what those derivations
are supposed to produce cannot catch a script that derives something else, so
the derivations are evaluated here against the real script text instead.

Only the constructs the script uses to declare paths and allowlists are
understood:

* ``$name = <expression>`` and ``$Global:name = <expression>``;
* ``if (<condition>) { $name = <expression> }``, which is how the script
  substitutes a literal for an environment variable the guest left unset;
* ``@( ... )`` array literals, on one line or several;
* expressions built from ``'literals'``, ``$variables``, ``$env:VARIABLES``,
  ``Join-Path``, ``Split-Path -Parent``, string concatenation with ``+``, and
  parentheses.

Anything else evaluates to None and leaves the assignment unresolved. In a
condition an unresolved expression is falsy, which is how PowerShell treats the
``$null`` an unset variable holds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Mapping

_ASSIGNMENT: Final = re.compile(r"\$(?:Global:)?(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<expression>\S.*)")
_CONDITIONAL_ASSIGNMENT: Final = re.compile(r"if\s*\(\s*(?P<condition>.+?)\s*\)\s*\{\s*(?P<assignment>\$.+?)\s*\}")
_NOT: Final = re.compile(r"-not\s+(?P<operand>.+)")
_ENDS_WITH: Final = re.compile(r"(?P<operand>.+?)\.EndsWith\(\s*'(?P<suffix>[^']*)'\s*\)")
_VARIABLE: Final = re.compile(r"\$(?:Global:)?(?P<name>[A-Za-z_]\w*)")
_ENVIRONMENT: Final = re.compile(r"\$env:(?P<name>[A-Za-z_]\w*)")
_LITERAL: Final = re.compile(r"'(?P<text>[^']*)'")
_SPLIT_PARENT: Final = re.compile(r"Split-Path\s+-Parent\s+(?P<operand>.+)")
_JOIN_PATH: Final = re.compile(r"Join-Path\s+(?P<base>.+?)\s+'(?P<leaf>[^']*)'")

_BRACKET_PAIRS: Final[dict[str, str]] = {"(": ")", "{": "}"}

_ERR_NOT_A_BRACKET: Final[str] = "a matching bracket was asked for from {char!r}, which is not an opening bracket"

_ARRAY_OPENING: Final[str] = "@("
_WINDOWS_SEPARATOR: Final[str] = "\\"
_WINDOWS_DRIVE_SEPARATOR: Final[str] = ":"


@dataclass(frozen=True)
class PowerShellScript:
    """Everything one evaluated script declared at top level.

    Attributes:
        variables: Scalar assignments that resolved, keyed by variable name and
            including ``PSScriptRoot`` itself.
        arrays: Array assignments whose every element resolved, keyed by
            variable name.
    """

    variables: dict[str, str]
    arrays: dict[str, tuple[str, ...]]


def split_path_parent(path: str) -> str:
    r"""Evaluate PowerShell's ``Split-Path -Parent`` on a Windows path.

    A path directly below a drive root has that root - including its trailing
    separator - as its parent, which is what makes ``E:\monitor`` resolve to
    ``E:\`` rather than to ``E:``.

    Args:
        path: Absolute Windows path.

    Returns:
        str: The parent container, or an empty string when the path has none.
    """
    head, separator, _leaf = path.rstrip(_WINDOWS_SEPARATOR).rpartition(_WINDOWS_SEPARATOR)
    if not separator:
        return ""
    if head.endswith(_WINDOWS_DRIVE_SEPARATOR):
        return head + _WINDOWS_SEPARATOR
    return head


def join_path(base: str, leaf: str) -> str:
    """Evaluate PowerShell's ``Join-Path`` on a Windows path.

    Args:
        base: Container path, with or without a trailing separator.
        leaf: Relative path appended below it.

    Returns:
        str: The combined path with exactly one separator between the parts.
    """
    return f"{base.rstrip(_WINDOWS_SEPARATOR)}{_WINDOWS_SEPARATOR}{leaf}"


def _split_top_level(text: str, separator: str) -> list[str]:
    """Split ``text`` on a separator that is outside quotes and parentheses.

    Args:
        text: Expression source to split.
        separator: Single character to split on.

    Returns:
        list[str]: The parts, in order, with the separator removed.
    """
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quoted = False
    for char in text:
        if char == "'":
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
        elif not quoted and char == ")":
            depth -= 1
        if not quoted and depth == 0 and char == separator:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def matching_bracket(text: str, start: int) -> int:
    """Return the index of the bracket closing the one at ``start``.

    Brackets inside single-quoted strings are literal text and are skipped, so
    a ``'{'`` in a PowerShell literal does not open a block.

    Args:
        text: Source text to scan.
        start: Index of the opening bracket, which must be ``(`` or ``{``.

    Returns:
        int: Index of the matching closing bracket, or -1 when the text ends
        before it.

    Raises:
        ValueError: If ``text[start]`` is not a bracket this function pairs.
    """
    opening = text[start]
    closing = _BRACKET_PAIRS.get(opening)
    if closing is None:
        raise ValueError(_ERR_NOT_A_BRACKET.format(char=opening))
    depth = 0
    quoted = False
    for index in range(start, len(text)):
        char = text[index]
        if char == "'":
            quoted = not quoted
            continue
        if quoted:
            continue
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _strip_parentheses(expression: str) -> str:
    """Remove one layer of parentheses wrapping a whole expression.

    Args:
        expression: Expression source, already stripped of whitespace.

    Returns:
        str: The inner expression, or ``expression`` when it is not wrapped.
    """
    if not expression.startswith("(") or matching_bracket(expression, 0) != len(expression) - 1:
        return expression
    return expression[1:-1].strip()


def _evaluate_expression(
    expression: str,
    variables: Mapping[str, str],
    environment: Mapping[str, str],
) -> str | None:
    """Evaluate one path expression from the generated agent script.

    Args:
        expression: Expression source.
        variables: Variables resolved so far, including ``PSScriptRoot``.
        environment: Environment variables the modelled guest exports.

    Returns:
        str | None: The resolved value, or None when the expression is not one
        of the understood forms or reads something unresolved.
    """
    source = _strip_parentheses(expression.strip())

    operands = _split_top_level(source, "+")
    if len(operands) > 1:
        resolved = [_evaluate_expression(operand, variables, environment) for operand in operands]
        return None if any(part is None for part in resolved) else "".join(part for part in resolved if part is not None)

    literal = _LITERAL.fullmatch(source)
    if literal is not None:
        return literal["text"]

    exported = _ENVIRONMENT.fullmatch(source)
    if exported is not None:
        return environment.get(exported["name"])

    variable = _VARIABLE.fullmatch(source)
    if variable is not None:
        return variables.get(variable["name"])

    parent = _SPLIT_PARENT.fullmatch(source)
    if parent is not None:
        operand = _evaluate_expression(parent["operand"], variables, environment)
        return None if operand is None else split_path_parent(operand)

    join = _JOIN_PATH.fullmatch(source)
    if join is not None:
        base = _evaluate_expression(join["base"], variables, environment)
        return None if base is None else join_path(base, join["leaf"])

    return None


def _evaluate_condition(
    condition: str,
    variables: Mapping[str, str],
    environment: Mapping[str, str],
) -> bool:
    """Evaluate one ``if`` condition from the generated agent script.

    Args:
        condition: Condition source between the parentheses.
        variables: Variables resolved so far.
        environment: Environment variables the modelled guest exports.

    Returns:
        bool: The condition's truth value, with an expression that does not
        resolve treated as the falsy ``$null`` an unset variable holds.
    """
    source = condition.strip()

    negation = _NOT.fullmatch(source)
    if negation is not None:
        return not _evaluate_condition(negation["operand"], variables, environment)

    ends_with = _ENDS_WITH.fullmatch(source)
    if ends_with is not None:
        value = _evaluate_expression(ends_with["operand"], variables, environment)
        return value is not None and value.endswith(ends_with["suffix"])

    return bool(_evaluate_expression(source, variables, environment))


def _evaluate_array(
    block: str,
    variables: Mapping[str, str],
    environment: Mapping[str, str],
) -> tuple[str, ...] | None:
    """Evaluate the elements of an ``@( ... )`` array literal.

    Args:
        block: Source between the array's parentheses.
        variables: Variables resolved so far.
        environment: Environment variables the modelled guest exports.

    Returns:
        tuple[str, ...] | None: The evaluated elements, or None when any
        element does not resolve.
    """
    elements = [element.strip() for element in _split_top_level(block, ",")]
    values = [_evaluate_expression(element, variables, environment) for element in elements if element]
    if not values or any(value is None for value in values):
        return None
    return tuple(value for value in values if value is not None)


def _apply_assignment(
    statement: str,
    script: PowerShellScript,
    environment: Mapping[str, str],
    remainder: str,
) -> int:
    """Apply one assignment statement to the accumulating script state.

    Args:
        statement: The assignment source, stripped of surrounding whitespace.
        script: Script state updated in place.
        environment: Environment variables the modelled guest exports.
        remainder: The script text from this statement onwards, used to read an
            array literal that continues on the following lines.

    Returns:
        int: Number of additional lines the statement consumed.
    """
    assignment = _ASSIGNMENT.fullmatch(statement)
    if assignment is None:
        return 0

    expression = assignment["expression"].strip()
    if not expression.startswith(_ARRAY_OPENING):
        value = _evaluate_expression(expression, script.variables, environment)
        if value is not None:
            script.variables[assignment["name"]] = value
        return 0

    if _ARRAY_OPENING not in remainder:
        return 0
    opening = remainder.index(_ARRAY_OPENING) + 1
    closing = matching_bracket(remainder, opening)
    if closing < 0:
        return 0
    values = _evaluate_array(remainder[opening + 1 : closing], script.variables, environment)
    if values is not None:
        script.arrays[assignment["name"]] = values
    return remainder.count("\n", 0, closing)


def evaluate_script(
    body: str,
    *,
    script_root: str,
    environment: Mapping[str, str],
) -> PowerShellScript:
    """Resolve the paths and arrays a PowerShell script declares at top level.

    Args:
        body: Full text of the script.
        script_root: In-guest directory the script was started from, which is
            what ``$PSScriptRoot`` holds while it runs.
        environment: Environment variables the modelled guest exports.

    Returns:
        PowerShellScript: Every top-level declaration that resolved.
    """
    script = PowerShellScript(variables={"PSScriptRoot": script_root}, arrays={})
    lines = body.splitlines()
    index = 0
    while index < len(lines):
        statement = lines[index].strip()
        conditional = _CONDITIONAL_ASSIGNMENT.fullmatch(statement)
        if conditional is not None:
            if _evaluate_condition(conditional["condition"], script.variables, environment):
                _apply_assignment(conditional["assignment"].strip(), script, environment, "")
            index += 1
            continue
        index += 1 + _apply_assignment(statement, script, environment, "\n".join(lines[index:]))
    return script
