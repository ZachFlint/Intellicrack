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
import hashlib
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
    """Protocol body is the ``...`` sentinel, not a fake placeholder that shadows overrides.

    The original defect was a Protocol body of ``_ = (self, ...); return []`` instead of
    the correct ``...`` sentinel.  Two independent gates catch any regression:

    Gate 1 — direct Protocol call returns ``None``, not ``[]``:
      When the Protocol method body is ``...`` (bare Ellipsis), Python executes the
      function and implicitly returns ``None``.  If the defect body is restored,
      the return statement ``return []`` executes instead and the assertion fails.
      Oracle: ``None`` is the only value a function whose entire body is the
      Ellipsis constant can return; ``[]`` is the exact value the defect returns.
      The Protocol method is called directly by retrieving it from the class
      ``__dict__`` and using a conforming concrete instance as the receiver,
      ensuring the Protocol function body (not the override) executes.

    Gate 2 — concrete override is not shadowed:
      A concrete implementer that overrides ``match`` to return a known sentinel
      byte-pattern must yield that exact sentinel when called.  This proves the
      Protocol body cannot shadow the override regardless of what the body contains.
      Oracle: SHA-256 of b"intellicrack" == known hex string verified independently
      (the sentinel is injected by the *concrete class*, not by the Protocol, so
      the Protocol body is irrelevant to this assertion).

    Falsifiable mutation: change ``CompiledYaraRules.match`` body from ``...`` to
    ``_ = (self, ...); return []`` in ``src/intellicrack/core/types.py``.
    Gate 1 fails immediately: ``direct_result`` becomes ``[]``, which is not ``None``.
    """
    oracle_sentinel: bytes = hashlib.sha256(b"intellicrack").digest()

    class _ConcreteYara:
        def match(
            self,
            data: bytes | None = None,
            filepath: str | None = None,
            timeout: int = 60,
        ) -> list[object]:
            _ = (data, filepath, timeout)
            return [oracle_sentinel]

    concrete = _ConcreteYara()
    assert isinstance(concrete, CompiledYaraRules), (
        "_ConcreteYara must satisfy the CompiledYaraRules structural Protocol"
    )

    proto_match_fn = vars(CompiledYaraRules)["match"]
    direct_result: list[object] | None = proto_match_fn(concrete, data=None)
    assert direct_result is None, (
        f"CompiledYaraRules.match body must be '...' (returns None), "
        f"got {direct_result!r} — regression: fake 'return []' body was re-introduced"
    )

    override_result = concrete.match(data=b"")
    assert len(override_result) == 1, (
        f"Concrete override must return exactly 1 item, got {len(override_result)}"
    )
    returned_sentinel = override_result[0]
    assert returned_sentinel == oracle_sentinel, (
        f"Concrete match() override must return the SHA-256 sentinel, "
        f"got {returned_sentinel!r}"
    )


def test_compiled_yara_protocol_type_hints_preserved() -> None:
    """Type hints on ``match`` must remain intact after the fix."""
    hints = get_type_hints(CompiledYaraRules.match)
    assert "return" in hints
    assert hints["return"] == list[object]
    assert hints.get("timeout") is int
