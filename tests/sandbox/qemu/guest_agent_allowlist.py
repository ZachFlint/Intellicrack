# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Evaluation of the command allowlist the generated Windows agent enforces.

``QEMUSandbox._windows_agent_script_content`` writes a ``Test-AllowedCommand``
helper into the in-guest ``agent.ps1``, and every command the host dispatches
over the agent channel is answered with ``command not in allowlist`` unless
that helper accepts it. Neither the roots it accepts nor the decision it makes
is knowable from the host: the roots are built in the guest from the drive
letter the guest gave the shared volume and from the ``%SystemRoot%`` the guest
reports, so a host-side copy of the rule can only ever restate what its author
believed the guest does.

This module therefore does not restate the rule - it reads it. The script's
own ``$allowedNames`` and ``$allowedRoots`` are resolved with
:func:`tests.sandbox.qemu.powershell_script.evaluate_script`, the body of
``Test-AllowedCommand`` is parsed out of the same script text, and a dispatched
command is decided by executing that body. A change to the helper - a dropped
check, a removed name, a root built from something else - changes the answer
here, which is the only way a test can gate a rule that runs inside the guest.

The statements and expressions the helper is built from are understood:
``if`` and ``foreach`` blocks, ``return $true``/``return $false``, assignment,
``[string]::IsNullOrEmpty``, ``-not``, ``-contains``, ``.ToLower()``,
``.EndsWith()`` and ``.StartsWith()``, over ``'literals'``, ``$variables`` and
the arrays the script declared. Anything else raises
:class:`GuestAllowlistError` rather than being skipped, because a helper this
module cannot execute is one whose decision it must not claim to know.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from tests.sandbox.qemu.powershell_script import evaluate_script, matching_bracket


if TYPE_CHECKING:
    from collections.abc import Mapping

_ALLOWLIST_FUNCTION: Final[str] = "Test-AllowedCommand"

_FUNCTION_HEADER: Final = re.compile(r"function\s+(?P<name>[A-Za-z][\w-]*)\s*\(\s*\$(?P<parameter>\w+)\s*\)\s*\{")
_IF_HEADER: Final = re.compile(r"if\s*\(")
_FOREACH_HEADER: Final = re.compile(r"foreach\s*\(\s*\$(?P<variable>\w+)\s+in\s+(?P<collection>\$\w+)\s*\)\s*\{")
_RETURN: Final = re.compile(r"return\s+\$(?P<value>true|false)")
_ASSIGNMENT: Final = re.compile(r"\$(?P<name>\w+)\s*=\s*(?P<expression>\S.*)")
_NOT: Final = re.compile(r"-not\s+(?P<operand>.+)")
_IS_NULL_OR_EMPTY: Final = re.compile(r"\[string\]::IsNullOrEmpty\((?P<operand>.*)\)")
_LITERAL: Final = re.compile(r"'(?P<text>[^']*)'")
_VARIABLE: Final = re.compile(r"\$(?P<name>\w+)")
_METHOD: Final = re.compile(r"\.(?P<name>[A-Za-z]\w*)\(")

_CONTAINS_OPERATOR: Final[str] = "-contains"
_BLOCK_OPENING: Final[str] = "{"
_LOWER_METHOD: Final[str] = "ToLower"
_ENDS_WITH_METHOD: Final[str] = "EndsWith"
_STARTS_WITH_METHOD: Final[str] = "StartsWith"

_ERR_NO_FUNCTION: Final[str] = "the generated agent script declares no {name} function"
_ERR_UNTERMINATED_BLOCK: Final[str] = "the block opened in {source!r} is never closed"
_ERR_NO_BLOCK: Final[str] = "{source!r} opens no block"
_ERR_UNMODELLED_STATEMENT: Final[str] = "{name} contains the unmodelled statement {source!r}"
_ERR_UNMODELLED_EXPRESSION: Final[str] = "{name} contains the unmodelled expression {source!r}"
_ERR_UNMODELLED_METHOD: Final[str] = "{name} calls the unmodelled method {method!r} in {source!r}"
_ERR_UNDECLARED_VARIABLE: Final[str] = "{name} reads ${variable}, which the script never declares"
_ERR_NOT_A_STRING: Final[str] = "{source!r} evaluated to {value!r}, which is not a string"
_ERR_NOT_AN_ARRAY: Final[str] = "{source!r} evaluated to {value!r}, which is not an array"
_ERR_METHOD_TAKES_NO_ARGUMENT: Final[str] = "{method} takes no argument, but {argument!r} was passed"


type _Value = str | bool | tuple[str, ...]
"""Everything an expression in the modelled helper can evaluate to."""

type _Statement = _Return | _Assignment | _Conditional | _ForEach
"""Everything the modelled helper can be built from."""


class GuestAllowlistError(RuntimeError):
    """A generated agent script this module cannot execute faithfully."""


@dataclass(frozen=True)
class _Return:
    """A ``return $true`` or ``return $false`` statement.

    Attributes:
        value: The boolean the helper hands back.
    """

    value: bool


@dataclass(frozen=True)
class _Assignment:
    """A ``$name = <expression>`` statement.

    Attributes:
        name: Variable assigned to, without its ``$``.
        expression: Unevaluated source of the assigned expression.
    """

    name: str
    expression: str


@dataclass(frozen=True)
class _Conditional:
    """An ``if (<condition>) { ... }`` statement.

    Attributes:
        condition: Unevaluated source between the condition's parentheses.
        consequence: Statements guarded by the condition.
    """

    condition: str
    consequence: tuple[_Statement, ...]


@dataclass(frozen=True)
class _ForEach:
    """A ``foreach ($item in $collection) { ... }`` statement.

    Attributes:
        variable: Loop variable, without its ``$``.
        collection: Unevaluated source of the iterated collection.
        body: Statements run once per element.
    """

    variable: str
    collection: str
    body: tuple[_Statement, ...]


def _as_string(value: _Value, source: str) -> str:
    """Require an expression to have evaluated to a string.

    Args:
        value: Value the expression evaluated to.
        source: Source of the expression, for the failure message.

    Returns:
        str: The value itself.

    Raises:
        GuestAllowlistError: If the expression evaluated to anything else.
    """
    if not isinstance(value, str):
        raise GuestAllowlistError(_ERR_NOT_A_STRING.format(source=source, value=value))
    return value


def _as_array(value: _Value, source: str) -> tuple[str, ...]:
    """Require an expression to have evaluated to an array.

    Args:
        value: Value the expression evaluated to.
        source: Source of the expression, for the failure message.

    Returns:
        tuple[str, ...]: The array itself.

    Raises:
        GuestAllowlistError: If the expression evaluated to anything else.
    """
    if not isinstance(value, tuple):
        raise GuestAllowlistError(_ERR_NOT_AN_ARRAY.format(source=source, value=value))
    return value


def _split_operator(expression: str, operator: str) -> tuple[str, str] | None:
    """Split an expression on a binary operator outside quotes and parentheses.

    Args:
        expression: Expression source to split.
        operator: Operator token to split on, without its surrounding spaces.

    Returns:
        tuple[str, str] | None: The operands, or None when the operator does
        not appear at the top level of the expression.
    """
    token = f" {operator} "
    depth = 0
    quoted = False
    for index, char in enumerate(expression):
        if char == "'":
            quoted = not quoted
            continue
        if quoted:
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and expression.startswith(token, index):
            return expression[:index], expression[index + len(token) :]
    return None


def _split_method_call(expression: str) -> tuple[str, str, str] | None:
    """Split an expression whose outermost operation is a method call.

    Args:
        expression: Expression source to split.

    Returns:
        tuple[str, str, str] | None: The target source, the method name and the
        argument source, or None when the expression is not a method call on
        its whole target.
    """
    depth = 0
    quoted = False
    for index, char in enumerate(expression):
        if char == "'":
            quoted = not quoted
            continue
        if quoted:
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "." and depth == 0:
            call = _METHOD.match(expression, index)
            if call is None:
                continue
            opening = call.end() - 1
            closing = matching_bracket(expression, opening)
            if closing != len(expression) - 1:
                continue
            return expression[:index], call["name"], expression[opening + 1 : closing]
    return None


def _invoke(method: str, target: _Value, argument: str, scope: Mapping[str, _Value], source: str) -> _Value:
    """Evaluate one ``.Method(...)`` call on an already evaluated target.

    Args:
        method: Name of the called method.
        target: Value the call's target evaluated to.
        argument: Unevaluated source of the call's argument.
        scope: Variables in scope while the helper runs.
        source: Source of the whole call, for failure messages.

    Returns:
        _Value: The call's result.

    Raises:
        GuestAllowlistError: If the method is not one this module models, or if
            an argument is passed to one that takes none.
    """
    text = _as_string(target, source)
    if method == _LOWER_METHOD:
        if argument.strip():
            raise GuestAllowlistError(_ERR_METHOD_TAKES_NO_ARGUMENT.format(method=_LOWER_METHOD, argument=argument))
        return text.lower()
    if method == _ENDS_WITH_METHOD:
        return text.endswith(_as_string(_evaluate(argument, scope), argument))
    if method == _STARTS_WITH_METHOD:
        return text.startswith(_as_string(_evaluate(argument, scope), argument))
    raise GuestAllowlistError(_ERR_UNMODELLED_METHOD.format(name=_ALLOWLIST_FUNCTION, method=method, source=source))


def _evaluate(source: str, scope: Mapping[str, _Value]) -> _Value:
    """Evaluate one expression from the modelled helper.

    Args:
        source: Expression source.
        scope: Variables in scope while the helper runs.

    Returns:
        _Value: The value the expression holds for this scope.

    Raises:
        GuestAllowlistError: If the expression is not one this module models,
            or reads a variable the script never declared.
    """
    expression = source.strip()
    while expression.startswith("(") and matching_bracket(expression, 0) == len(expression) - 1:
        expression = expression[1:-1].strip()

    negation = _NOT.fullmatch(expression)
    if negation is not None:
        return not _evaluate(negation["operand"], scope)

    contains = _split_operator(expression, _CONTAINS_OPERATOR)
    if contains is not None:
        collection, member = contains
        return _as_string(_evaluate(member, scope), member) in _as_array(_evaluate(collection, scope), collection)

    empty = _IS_NULL_OR_EMPTY.fullmatch(expression)
    if empty is not None:
        return not _as_string(_evaluate(empty["operand"], scope), empty["operand"])

    call = _split_method_call(expression)
    if call is not None:
        target, method, argument = call
        return _invoke(method, _evaluate(target, scope), argument, scope, expression)

    literal = _LITERAL.fullmatch(expression)
    if literal is not None:
        return literal["text"]

    variable = _VARIABLE.fullmatch(expression)
    if variable is not None:
        value = scope.get(variable["name"])
        if value is None:
            raise GuestAllowlistError(_ERR_UNDECLARED_VARIABLE.format(name=_ALLOWLIST_FUNCTION, variable=variable["name"]))
        return value

    raise GuestAllowlistError(_ERR_UNMODELLED_EXPRESSION.format(name=_ALLOWLIST_FUNCTION, source=source))


def _parse_block(remainder: str, start: int) -> tuple[tuple[_Statement, ...], int]:
    """Parse the braced block a statement opens.

    Args:
        remainder: Script text from the statement's own line onwards, with
            every line already stripped of indentation.
        start: Index in ``remainder`` from which to look for the opening brace.

    Returns:
        tuple[tuple[_Statement, ...], int]: The block's statements and the
        number of additional lines it spans.

    Raises:
        GuestAllowlistError: If the statement opens no block, or opens one the
            script never closes.
    """
    opening = remainder.find(_BLOCK_OPENING, start)
    if opening < 0:
        raise GuestAllowlistError(_ERR_NO_BLOCK.format(source=remainder.splitlines()[0]))
    closing = matching_bracket(remainder, opening)
    if closing < 0:
        raise GuestAllowlistError(_ERR_UNTERMINATED_BLOCK.format(source=remainder.splitlines()[0]))
    return _parse_statements(remainder[opening + 1 : closing]), remainder.count("\n", 0, closing)


def _parse_statement(statement: str, remainder: str) -> tuple[_Statement, int]:
    """Parse one statement of the modelled helper.

    Args:
        statement: The statement's own line, stripped of indentation.
        remainder: Script text from that line onwards, likewise stripped, from
            which a statement that opens a block reads its body.

    Returns:
        tuple[_Statement, int]: The parsed statement and the number of
        additional lines it spans.

    Raises:
        GuestAllowlistError: If the statement is not one this module models.
    """
    returned = _RETURN.fullmatch(statement)
    if returned is not None:
        return _Return(value=returned["value"] == "true"), 0

    conditional = _IF_HEADER.match(statement)
    if conditional is not None:
        opening = conditional.end() - 1
        closing = matching_bracket(statement, opening)
        if closing < 0:
            raise GuestAllowlistError(_ERR_UNTERMINATED_BLOCK.format(source=statement))
        consequence, spanned = _parse_block(remainder, closing)
        return _Conditional(condition=statement[opening + 1 : closing], consequence=consequence), spanned

    loop = _FOREACH_HEADER.match(statement)
    if loop is not None:
        body, spanned = _parse_block(remainder, loop.end() - 1)
        return _ForEach(variable=loop["variable"], collection=loop["collection"], body=body), spanned

    assignment = _ASSIGNMENT.fullmatch(statement)
    if assignment is not None:
        return _Assignment(name=assignment["name"], expression=assignment["expression"].strip()), 0

    raise GuestAllowlistError(_ERR_UNMODELLED_STATEMENT.format(name=_ALLOWLIST_FUNCTION, source=statement))


def _parse_statements(block: str) -> tuple[_Statement, ...]:
    """Parse every statement of one block of the modelled helper.

    Args:
        block: Script text between the block's braces.

    Returns:
        tuple[_Statement, ...]: The block's statements, in order.
    """
    lines = [line.strip() for line in block.splitlines()]
    statements: list[_Statement] = []
    index = 0
    while index < len(lines):
        statement = lines[index]
        remainder = "\n".join(lines[index:])
        index += 1
        if not statement:
            continue
        parsed, spanned = _parse_statement(statement, remainder)
        statements.append(parsed)
        index += spanned
    return tuple(statements)


def _execute(statements: tuple[_Statement, ...], scope: dict[str, _Value]) -> bool | None:
    """Run the statements of one block against a scope.

    Args:
        statements: Statements to run, in order.
        scope: Variables in scope, updated in place by assignment and by a
            ``foreach`` binding its loop variable.

    Returns:
        bool | None: What the block returned, or None when it fell through
        without returning - which is the ``$null`` PowerShell hands back from a
        function whose statements all ran without a ``return``.
    """
    for statement in statements:
        if isinstance(statement, _Return):
            return statement.value
        if isinstance(statement, _Assignment):
            scope[statement.name] = _evaluate(statement.expression, scope)
            continue
        if isinstance(statement, _Conditional):
            if _evaluate(statement.condition, scope):
                returned = _execute(statement.consequence, scope)
                if returned is not None:
                    return returned
            continue
        for element in _as_array(_evaluate(statement.collection, scope), statement.collection):
            scope[statement.variable] = element
            returned = _execute(statement.body, scope)
            if returned is not None:
                return returned
    return None


@dataclass(frozen=True)
class GuestCommandAllowlist:
    """The allowlist decision one generated agent script makes in one guest.

    Attributes:
        parameter: Name of the helper's parameter, without its ``$``, which the
            dispatched command is bound to.
        statements: The helper's body, as parsed from the script.
        declarations: Values the script declared at top level for this guest,
            including the ``$allowedNames`` and ``$allowedRoots`` the helper
            reads.
    """

    parameter: str
    statements: tuple[_Statement, ...]
    declarations: Mapping[str, _Value]

    def accepts(self, command: str) -> bool:
        """Decide one dispatched command the way the in-guest helper does.

        Args:
            command: Value of the request's ``command`` field, as the host
                dispatched it.

        Returns:
            bool: True when the agent would run the command, False when it
            would answer ``command not in allowlist``.
        """
        scope: dict[str, _Value] = {**self.declarations, self.parameter: command}
        return bool(_execute(self.statements, scope))

    def array(self, name: str) -> tuple[str, ...]:
        """Return one array the script declared for this guest.

        Args:
            name: Variable name, without its ``$``.

        Returns:
            tuple[str, ...]: The array's elements, in declaration order.

        Raises:
            GuestAllowlistError: If the script declares no such array.
        """
        value = self.declarations.get(name)
        if value is None:
            raise GuestAllowlistError(_ERR_UNDECLARED_VARIABLE.format(name=_ALLOWLIST_FUNCTION, variable=name))
        return _as_array(value, f"${name}")


def guest_command_allowlist(body: str, *, script_root: str, environment: Mapping[str, str]) -> GuestCommandAllowlist:
    """Read the allowlist a generated agent script enforces in one guest.

    Args:
        body: Full text of the generated ``agent.ps1``.
        script_root: In-guest directory the agent was started from, which is
            what ``$PSScriptRoot`` holds while it runs and what the share root
            - and so the first allowed root - is derived from.
        environment: Environment variables the modelled guest exports, from
            which the script derives the system roots it allows.

    Returns:
        GuestCommandAllowlist: The decision the script's ``Test-AllowedCommand``
        makes for that guest.

    Raises:
        GuestAllowlistError: If the script declares no ``Test-AllowedCommand``,
            or declares one whose block is never closed.
    """
    declared = evaluate_script(body, script_root=script_root, environment=environment)
    declarations: dict[str, _Value] = {**declared.variables, **declared.arrays}
    for header in _FUNCTION_HEADER.finditer(body):
        if header["name"] != _ALLOWLIST_FUNCTION:
            continue
        opening = header.end() - 1
        closing = matching_bracket(body, opening)
        if closing < 0:
            raise GuestAllowlistError(_ERR_UNTERMINATED_BLOCK.format(source=header.group()))
        return GuestCommandAllowlist(
            parameter=header["parameter"],
            statements=_parse_statements(body[opening + 1 : closing]),
            declarations=declarations,
        )
    raise GuestAllowlistError(_ERR_NO_FUNCTION.format(name=_ALLOWLIST_FUNCTION))
