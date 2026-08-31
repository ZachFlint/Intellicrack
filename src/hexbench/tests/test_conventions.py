# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The gate that keeps this directory to one way of asserting things.

Four suites were written in parallel against the same unusual constraint: this
directory sits outside the repository's ``tests/**`` lint scope, so a bare
``assert`` trips ``S101`` and ``self.assertEqual`` trips ``PT009``, and neither
may be suppressed. Left to themselves the suites solved it three different
ways -- module-level ``require_*`` functions duplicated verbatim across three
files, a ``GateCase`` base with its own vocabulary, and helpers aliased in
``setUp`` so the linter would stop recognising the call. All three now route
through :class:`hexbench.tests._support.Assertions`.

Nothing about a green suite prevents that from happening again, because every
one of those spellings passes every other gate in this package. So the
convention is asserted here directly.

The aliasing case is the one worth naming. Writing ``equal = self.assertEqual``
and then calling ``equal(...)`` satisfies the linter while still calling the
method the linter exists to discourage: it is a suppression that avoids
detection by renaming rather than by changing what the code does. The shared
helpers raise :class:`AssertionError` outright, which is what ``unittest``
reports as a failure anyway, so the rule is met rather than evaded.

Each check carries a control, since a scanner that has silently stopped
matching anything reports a clean bill of health.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path
from typing import Final

from ._support import Assertions


_MODULE_GLOB: Final = "test_*.py"
_ENCODING: Final = "utf-8"

_HELPER_PREFIX: Final = "require_"
_BRIEF: Final = "_brief"

_ASSERTION_PREFIX: Final = "assert"
_SELF: Final = "self"

_THIS_MODULE: Final = "test_conventions.py"
"""This file names the forbidden spellings in prose, so it scans everything but itself."""

_MINIMUM_MODULES: Final = 8
"""Floor on the module scan, so a scanner finding nothing cannot pass."""

_MINIMUM_CASES: Final = 20
"""Floor on the test-case scan, held for the same reason."""

_CONTROL_SOURCE: Final = """
class Case(unittest.TestCase):
    def setUp(self):
        self.equal = self.assertEqual

def require_equal(a, b, subject):
    raise AssertionError(subject)
"""
"""A module written the way the suites used to be, proving the scanners fire."""


def _test_modules() -> tuple[Path, ...]:
    """List the suite modules this gate holds to the convention.

    Returns:
        tuple[Path, ...]: Every ``test_*.py`` in this directory except this one.
    """
    here = Path(__file__).resolve().parent
    return tuple(sorted(p for p in here.glob(_MODULE_GLOB) if p.name != _THIS_MODULE))


def _declared_helpers(tree: ast.Module) -> frozenset[str]:
    """Find general-purpose assertion helpers a module defines for itself.

    Only module-level functions count. A ``require_``-prefixed *method* on a
    case is a domain-specific check over that suite's own subject -- whether a
    race ran enough iterations to have proved anything, say -- which belongs
    with the suite and is not the duplication this gate is looking for.

    Args:
        tree: Parsed module.

    Returns:
        frozenset[str]: Names of any module-level ``require_*`` or ``_brief``
        function.
    """
    return frozenset(
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and (node.name.startswith(_HELPER_PREFIX) or node.name == _BRIEF)
    )


def _aliased_assertions(tree: ast.Module) -> frozenset[str]:
    """Find unittest assertion methods bound to a plain name.

    Detects ``equal = self.assertEqual`` and ``self.equal = self.assertEqual``
    alike, by looking at what is being assigned rather than at what it is
    called.

    Args:
        tree: Parsed module.

    Returns:
        frozenset[str]: The assertion methods found bound to another name.
    """
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not isinstance(value, ast.Attribute) or not value.attr.startswith(_ASSERTION_PREFIX):
            continue
        origin = value.value
        if isinstance(origin, ast.Name) and origin.id == _SELF:
            found.add(value.attr)
    return frozenset(found)


def _cases() -> tuple[type[unittest.TestCase], ...]:
    """Collect every test case the suite actually runs.

    Returns:
        tuple[type[unittest.TestCase], ...]: The loaded test classes.
    """
    here = Path(__file__).resolve().parent
    suite = unittest.TestLoader().discover(str(here), top_level_dir=str(here.parent.parent))
    collected: set[type[unittest.TestCase]] = set()

    def walk(item: unittest.TestSuite | unittest.TestCase) -> None:
        if isinstance(item, unittest.TestSuite):
            for child in item:
                walk(child)
            return
        collected.add(type(item))

    walk(suite)
    return tuple(sorted(collected, key=lambda c: (c.__module__, c.__name__)))


class AssertionConventionTests(Assertions, unittest.TestCase):
    """One vocabulary, defined once, inherited everywhere."""

    def test_no_suite_defines_its_own_assertion_helper(self) -> None:
        """An assertion helper belongs in ``_support``, so there is one of it."""
        modules = _test_modules()
        self.require(
            len(modules) >= _MINIMUM_MODULES,
            f"the module scan found only {len(modules)} suites, too few to be reading this directory",
        )
        offenders = {path.name: sorted(_declared_helpers(ast.parse(path.read_text(encoding=_ENCODING)))) for path in modules}
        named = {name: helpers for name, helpers in offenders.items() if helpers}
        self.require_same(
            named,
            {},
            "these suites define assertion helpers of their own; hoist them into _support so there is a single definition",
        )

    def test_no_suite_aliases_a_unittest_assertion(self) -> None:
        """Renaming the call is a suppression that evades the rule rather than meeting it."""
        modules = _test_modules()
        offenders = {path.name: sorted(_aliased_assertions(ast.parse(path.read_text(encoding=_ENCODING)))) for path in modules}
        named = {name: aliased for name, aliased in offenders.items() if aliased}
        self.require_same(
            named,
            {},
            "these suites bind a unittest assertion method to another name; use the shared helpers in _support instead",
        )

    def test_every_test_case_inherits_the_shared_vocabulary(self) -> None:
        """``self.equal`` must mean the same thing in every suite that calls it."""
        cases = _cases()
        self.require(
            len(cases) >= _MINIMUM_CASES,
            f"the case scan found only {len(cases)} test classes, too few to be reading this suite",
        )
        stray = sorted(f"{case.__module__}.{case.__name__}" for case in cases if not issubclass(case, Assertions))
        self.require_same(stray, [], "these test cases do not inherit Assertions, so their assertions are not the shared ones")

    def test_the_scanners_detect_the_convention_they_forbid(self) -> None:
        """The control: a module written the old way must trip both scanners."""
        tree = ast.parse(_CONTROL_SOURCE)
        self.require_same(sorted(_declared_helpers(tree)), ["require_equal"], "the helper scanner missed a locally defined helper")
        self.require_same(sorted(_aliased_assertions(tree)), ["assertEqual"], "the alias scanner missed an aliased assertion")
