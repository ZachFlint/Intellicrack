# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for F-0022 ``CompiledYaraRules`` Protocol convention.

Asserts that the ``CompiledYaraRules.match`` body is ``...`` (the
Protocol convention) rather than the previous fake
``_ = (self, ...); return []`` placeholder. The check is performed both
structurally and at runtime: ``CompiledYaraRules`` must be a
``typing.Protocol`` and any concrete implementer must be able to
override ``match`` without being shadowed by the placeholder.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Protocol, get_type_hints

from intellicrack.core.types import CompiledYaraRules


def test_compiled_yara_rules_is_protocol() -> None:
    """``CompiledYaraRules`` must be a ``typing.Protocol`` subclass."""
    assert issubclass(CompiledYaraRules, Protocol)
    assert getattr(CompiledYaraRules, "_is_protocol", False) is True


def test_compiled_yara_match_body_is_ellipsis() -> None:
    """The ``match`` body must be the Protocol ``...`` placeholder.

    Parses the actual ``types.py`` source to assert the method body is
    a single ``...`` statement. This guards against regressions that
    re-introduce fake-success returns like ``return []``.
    """
    types_path = Path(inspect.getsourcefile(CompiledYaraRules) or "")
    assert types_path.exists()

    module_ast = ast.parse(types_path.read_text(encoding="utf-8"))
    target: ast.FunctionDef | None = None
    for node in ast.walk(module_ast):
        if isinstance(node, ast.ClassDef) and node.name == "CompiledYaraRules":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "match":
                    target = item
                    break
            break

    assert target is not None, "CompiledYaraRules.match not found"

    body = target.body
    docstring = ast.get_docstring(target, clean=False)
    assert docstring is not None

    non_doc_statements = body[1:] if body and isinstance(body[0], ast.Expr) else body
    assert len(non_doc_statements) == 1, (
        f"CompiledYaraRules.match body must contain exactly one statement (...), got {len(non_doc_statements)}"
    )

    only_stmt = non_doc_statements[0]
    assert isinstance(only_stmt, ast.Expr), "Protocol body must be a single bare ellipsis"
    assert isinstance(only_stmt.value, ast.Constant)
    assert only_stmt.value.value is Ellipsis


def test_compiled_yara_concrete_implementation_overrides_protocol() -> None:
    """A concrete class must be able to implement ``match`` without inheriting an empty list.

    The previous fake body returned ``[]`` even when called via
    ``super().match(...)``; with the proper Protocol body, concrete
    implementations are the sole source of truth for the return value.
    """

    class _RealYaraRules:
        """Real implementation of ``CompiledYaraRules`` for the assertion.

        Returns:
            list[object]: A non-empty list to prove the protocol body
            does not shadow the implementation.
        """

        def match(
            self,
            data: bytes | None = None,
            filepath: str | None = None,
            timeout: int = 60,
        ) -> list[object]:
            """Return a sentinel non-empty list.

            Args:
                data: Ignored.
                filepath: Ignored.
                timeout: Ignored.

            Returns:
                list[object]: ``["match"]`` to prove the override took.
            """
            del data, filepath, timeout
            return ["match"]

    rules: CompiledYaraRules = _RealYaraRules()
    assert isinstance(rules, CompiledYaraRules)
    assert rules.match(data=b"abc") == ["match"]


def test_compiled_yara_protocol_type_hints_preserved() -> None:
    """Type hints on ``match`` must remain intact after the fix."""
    hints = get_type_hints(CompiledYaraRules.match)
    assert "return" in hints
    assert hints["return"] == list[object]
    assert hints.get("timeout") is int
