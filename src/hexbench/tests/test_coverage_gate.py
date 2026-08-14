# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The gate that fails when hexbench stops covering the whole engine.

hexbench claims to expose every callable ``intellicrack_hexcore`` has. That
claim decays in four different ways, and this module holds one layer against
each of them.

The first layer compares the catalogue against live introspection of the
compiled module. If the two disagree there is a callable the GUI cannot see at
all, and nothing further is worth checking.

The second layer posts every catalogued name at the real routing table. A
missing-argument rejection is a pass: the point is that the name resolved to an
operation rather than falling through to the not-found handler. A fabricated
name is posted alongside as a control, because a routing test that cannot
produce a 404 is not testing routing.

The third layer runs all of them. :mod:`hexbench.tests._recipes` holds one
argument-producing recipe per operation, so the day a ninety-first method lands
in the Rust crate the table reports ``no invocation recipe for: [...]`` and this
suite fails until somebody decides how the new operation should be driven. Every
recipe is then executed against the live engine and its outcome checked, which
is what catches an operation that is catalogued and routable but broken.

The fourth layer reads the browser assets. The first three layers all pass
happily when an operation is *renamed*: the catalogue follows the engine, the
router follows the catalogue, and the recipe table is corrected along with them,
while ``renderers.js`` keeps a view registered under the dead name and quietly
falls back to the generic renderer forever. So every operation name the frontend
mentions -- in its renderer registry, its manifests, and at its literal call
sites -- is checked against the catalogue. The scanner that reads those files is
itself held to a control, since a scanner that has silently stopped matching
anything reports a clean bill of health.
"""

from __future__ import annotations

import re
import unittest
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from hexbench.catalog import Receiver, build_catalog, operation_names, runtime_surface
from hexbench.dispatch import operation_for
from hexbench.reference import raw_capable_operations

from ._recipes import RECIPES, coverage_gap, missing_recipes, recipe_for, unknown_recipes
from ._support import STATIC_ROOT, Assertions, HexbenchTestCase, error_of, require_encodable


if TYPE_CHECKING:
    from collections.abc import Callable

    from hexbench.dispatch import InvocationResult


_STATUS_OK: Final = 200
_STATUS_NOT_FOUND: Final = 404

_KIND_KEY: Final = "kind"
_UNKNOWN_OPERATION_KIND: Final = "unknown_operation"
_NO_SUCH_ROUTE_KIND: Final = "no_such_route"
_UNROUTABLE_KINDS: Final[frozenset[str]] = frozenset({_UNKNOWN_OPERATION_KIND, _NO_SUCH_ROUTE_KIND})

_ABSENT_OPERATION: Final = "hexbench_operation_that_does_not_exist"
"""A name the engine cannot possibly expose, used as the routing control."""

_STALE_CONTROL: Final = "hexbench_renamed_away_operation"
"""A name the scanner control plants, standing in for a renamed operation."""

_CONTROL_SYMBOL: Final = "CONTROL"
"""Declaration name the scanner controls read from their synthetic sources."""

_JS_GLOB: Final = "*.js"
_ENCODING: Final = "utf-8"

_QUOTES: Final = "'\"`"
_OPENERS: Final = "([{"
_CLOSERS: Final = ")]}"
_ESCAPE: Final = "\\"
_TERMINATOR: Final = ";"
_LINE_COMMENT: Final = "//"
_BLOCK_COMMENT_OPEN: Final = "/*"
_BLOCK_COMMENT_CLOSE: Final = "*/"
_NEWLINE: Final = "\n"
_QUALIFIER: Final = "."

_OPERATION_SHAPE: Final = re.compile(r"^[a-z][a-z0-9_]*$")
"""Shape every engine operation name has, and no shell command identifier has."""

_CALL_SITE: Final = re.compile(r"\b(?:callOp|callOpRaw|openOperation|fetchRaw|run)\(\s*(?P<quote>['\"])(?P<name>[^'\"\\\\]*)(?P=quote)")
"""A frontend call passing an operation name as a literal first argument."""

_LITERAL: Final = re.compile(r"(?P<quote>['\"])(?P<name>[^'\"\\\\]*)(?P=quote)")
"""Any string literal inside a manifest body."""

_PAIR_KEY: Final = re.compile(r"\[\s*(?P<quote>['\"])(?P<name>[^'\"\\\\]*)(?P=quote)")
"""The first literal of a bracketed pair, which is the key of a map entry."""

_DECLARATION: Final = "(?:export )?const {symbol}\\s*=\\s*"

_MINIMUM_MANIFEST_NAMES: Final = 45
"""Floor on the manifest scan, so a scanner matching nothing cannot pass."""

_MINIMUM_CALL_SITE_NAMES: Final = 20
"""Floor on the call-site scan, held for the same reason."""

_NOTHING: Final = 0


class ManifestError(LookupError):
    """Raised when a frontend manifest this gate reads is no longer there."""


def _declaration_body(source: str, symbol: str) -> str:
    """Extract the initialiser of one top-level ``const`` declaration.

    The body is delimited by scanning rather than by a regular expression,
    because the manifests are nested bracket literals and a pattern that stops
    at the first ``]`` would read a fraction of one and report a clean result
    from it. Comments are dropped as they are passed, so a commented-out entry
    is not read back as a live registration.

    Args:
        source: Complete text of a JavaScript module.
        symbol: Name of the declaration to extract.

    Returns:
        str: Code between the ``=`` and the semicolon that ends the statement,
        with any comments removed.

    Raises:
        ManifestError: If the module declares no such symbol, or the statement
            is never terminated.
    """
    opening = re.search(_DECLARATION.format(symbol=re.escape(symbol)), source, re.MULTILINE)
    if opening is None:
        message = f"no top-level declaration of {symbol!r}; the frontend manifest this gate reads has been renamed or removed"
        raise ManifestError(message)
    body: list[str] = []
    depth = 0
    quote = ""
    escaped = False
    index = opening.end()
    while index < len(source):
        char = source[index]
        if quote:
            if escaped:
                escaped = False
            elif char == _ESCAPE:
                escaped = True
            elif char == quote:
                quote = ""
        elif source.startswith(_LINE_COMMENT, index):
            newline = source.find(_NEWLINE, index)
            index = len(source) if newline < 0 else newline
            continue
        elif source.startswith(_BLOCK_COMMENT_OPEN, index):
            closing = source.find(_BLOCK_COMMENT_CLOSE, index + len(_BLOCK_COMMENT_OPEN))
            index = len(source) if closing < 0 else closing + len(_BLOCK_COMMENT_CLOSE)
            continue
        elif char in _QUOTES:
            quote = char
        elif char in _OPENERS:
            depth += 1
        elif char in _CLOSERS:
            depth -= 1
        elif char == _TERMINATOR and depth == 0:
            return "".join(body)
        body.append(char)
        index += 1
    message = f"declaration of {symbol!r} is never terminated"
    raise ManifestError(message)


def _shaped(candidates: frozenset[str]) -> frozenset[str]:
    """Keep only the names that could name an engine operation.

    Shell command identifiers are qualified (``search.find``) and the frontend
    passes an empty string where it means "no operation at all", so both fall
    away here without any name having to be listed.

    Args:
        candidates: Raw string literals lifted out of a module.

    Returns:
        frozenset[str]: The subset shaped like an operation name.
    """
    return frozenset(candidate for candidate in candidates if _OPERATION_SHAPE.match(candidate))


def _all_literals(body: str) -> frozenset[str]:
    """Read every string literal in a manifest body.

    Args:
        body: Initialiser text of a manifest declaration.

    Returns:
        frozenset[str]: Operation-shaped literals found anywhere in the body.
    """
    return _shaped(frozenset(match.group("name") for match in _LITERAL.finditer(body)))


def _pair_keys(body: str) -> frozenset[str]:
    """Read the key of every bracketed pair in a manifest body.

    Map entries are written ``['export_patches_ips', 'ips']``, where only the
    first member names an operation. Taking every literal instead would ask the
    catalogue for a file extension.

    Args:
        body: Initialiser text of a manifest declaration.

    Returns:
        frozenset[str]: Operation-shaped keys of the body's entries.
    """
    return _shaped(frozenset(match.group("name") for match in _PAIR_KEY.finditer(body)))


def _qualified_pair_prefixes(body: str) -> frozenset[str]:
    """Read the operation half of every qualified key in a manifest body.

    A form default is keyed either by a bare parameter name, which applies
    everywhere, or by ``operation.parameter``, which does not. Only the
    qualified form names an operation.

    Args:
        body: Initialiser text of a manifest declaration.

    Returns:
        frozenset[str]: Operation-shaped prefixes of the body's qualified keys.
    """
    keys = (match.group("name") for match in _PAIR_KEY.finditer(body))
    return _shaped(frozenset(key.split(_QUALIFIER, 1)[0] for key in keys if _QUALIFIER in key))


@dataclass(frozen=True, slots=True)
class Manifest:
    """One frontend table that registers operations by name.

    Attributes:
        module: Leaf name of the JavaScript module holding the table.
        symbol: Name of the ``const`` declaration to read.
        extract: How to lift operation names out of the declaration's body.
    """

    module: str
    symbol: str
    extract: Callable[[str], frozenset[str]]

    @property
    def label(self) -> str:
        """Name this manifest the way a failure message should.

        Returns:
            str: The module and symbol, joined.
        """
        return f"{self.module}:{self.symbol}"

    def names(self) -> frozenset[str]:
        """Read the operation names this table registers.

        Propagates :class:`ManifestError` when the declaration has gone away,
        which is the correct outcome: a manifest that cannot be found can no
        longer be checked, and silence would be worse than a failure.

        Returns:
            frozenset[str]: Operation names the table mentions.
        """
        source = (STATIC_ROOT / self.module).read_text(encoding=_ENCODING)
        return self.extract(_declaration_body(source, self.symbol))


MANIFESTS: Final[tuple[Manifest, ...]] = (
    Manifest("renderers.js", "RENDERERS", _pair_keys),
    Manifest("renderers.js", "SEARCH_OPERATIONS", _all_literals),
    Manifest("renderers.js", "EXPORT_EXTENSIONS", _pair_keys),
    Manifest("panels.js", "SEARCH_OPERATIONS", _all_literals),
    Manifest("panels.js", "MUTATING_REFRESH", _all_literals),
    Manifest("panels.js", "EXPORT_FORMATS", _pair_keys),
    Manifest("forms.js", "TEMPLATE_OPERATIONS", _all_literals),
    Manifest("forms.js", "TRANSFORM_OPERATION", _all_literals),
    Manifest("forms.js", "CUSTOM_CRC_OPERATION", _all_literals),
    Manifest("forms.js", "DEFAULT_OVERRIDES", _qualified_pair_prefixes),
)
"""Every frontend table that names operations rather than deriving them.

The operation console and the command palette are absent on purpose: both build
themselves from ``/api/catalog`` and mention no operation by name, so there is
nothing in either that could go stale.
"""


def _call_sites(source: str) -> frozenset[str]:
    """Read every operation name a module passes as a literal.

    Args:
        source: Complete text of a JavaScript module.

    Returns:
        frozenset[str]: Operation-shaped names passed to a dispatching call.
    """
    return _shaped(frozenset(match.group("name") for match in _CALL_SITE.finditer(source)))


def _call_site_references() -> dict[str, frozenset[str]]:
    """Read the literal operation names of every browser module.

    Returns:
        dict[str, frozenset[str]]: Names each module dispatches by literal,
        keyed by module leaf name, omitting modules that dispatch none.
    """
    found: dict[str, frozenset[str]] = {}
    for path in sorted(STATIC_ROOT.glob(_JS_GLOB)):
        names = _call_sites(path.read_text(encoding=_ENCODING))
        if names:
            found[path.name] = names
    return found


class CatalogueCompletenessTests(Assertions, unittest.TestCase):
    """The catalogue must describe the whole compiled surface, and nothing else."""

    def test_catalogue_matches_the_live_runtime_surface(self) -> None:
        """Every public callable the extension exposes is catalogued, and no other."""
        document_names, module_names = runtime_surface()
        surface = document_names | module_names
        self.require(len(surface) > _NOTHING, "runtime introspection found no callables, so the comparison below would be vacuous")
        catalogued = operation_names()
        self.require(
            catalogued == surface,
            f"catalogue misses {sorted(surface - catalogued)} and invents {sorted(catalogued - surface)}",
        )

    def test_the_catalogue_populates_every_receiver_kind(self) -> None:
        """One entry per name, each grouped, and all four bindings represented."""
        catalog = build_catalog()
        self.require_same(len(catalog), len(operation_names()), "the catalogue holds two entries under one name")
        self.require_same(
            {operation.receiver for operation in catalog},
            set(Receiver),
            "the catalogue leaves a receiver kind unpopulated, so a dispatcher arm goes unexercised",
        )
        for operation in catalog:
            with self.subTest(operation=operation.name):
                self.require(bool(operation.group), f"{operation.name} carries no group label")


class RoutingReachabilityTests(HexbenchTestCase):
    """Every catalogued name must resolve at the HTTP surface."""

    def test_every_operation_resolves_to_a_route(self) -> None:
        """Posting a catalogued name never falls through to the not-found handler."""
        for name in sorted(operation_names()):
            with self.subTest(operation=name):
                response = self.session.post_operation(name)
                if response.status == _STATUS_OK:
                    continue
                kind = error_of(response).get(_KIND_KEY)
                self.require(kind not in _UNROUTABLE_KINDS, f"{name} did not resolve to an operation: {kind}")
                self.require(response.status != _STATUS_NOT_FOUND, f"{name} answered {response.status}")

    def test_an_absent_operation_does_not_resolve(self) -> None:
        """A name the engine does not expose is refused, so the check above can fail."""
        self.require(_ABSENT_OPERATION not in operation_names(), "the control name is a real operation; choose another")
        response = self.session.post_operation(_ABSENT_OPERATION)
        self.require_same(response.status, _STATUS_NOT_FOUND, "an unknown operation was routed somewhere")
        self.require_same(error_of(response).get(_KIND_KEY), _UNKNOWN_OPERATION_KIND, "an unknown operation failed for the wrong reason")


class RecipeTableTests(Assertions, unittest.TestCase):
    """The recipe table must stay joined to the catalogue."""

    def test_every_operation_has_an_invocation_recipe(self) -> None:
        """No catalogued operation is left with nothing that knows how to run it."""
        missing = missing_recipes()
        self.require(not missing, f"no invocation recipe for: {sorted(missing)}")

    def test_no_recipe_names_a_withdrawn_operation(self) -> None:
        """No recipe survives the operation it was written for."""
        unknown = unknown_recipes()
        self.require(not unknown, f"recipe names no catalogued operation: {sorted(unknown)}")

    def test_the_table_reports_no_coverage_gap(self) -> None:
        """The table's own reconciliation agrees with the two checks above."""
        self.require_same(coverage_gap(), "", "the recipe table and the catalogue disagree")

    def test_every_tolerated_failure_is_documented(self) -> None:
        """A recipe allowed to fail explains what its failure means."""
        for name, recipe in sorted(RECIPES.items()):
            if not recipe.tolerated:
                continue
            with self.subTest(operation=name):
                self.require(bool(recipe.note), f"{name} tolerates {sorted(recipe.tolerated)} without saying why")


class ExecutionCoverageTests(HexbenchTestCase):
    """Every catalogued operation must actually run against the live engine."""

    def _check_result(self, name: str, result: InvocationResult) -> None:
        """Check that one invocation returned a coherent, encodable result.

        Args:
            name: Operation that ran.
            result: What the dispatcher returned for it.
        """
        operation = operation_for(name)
        self.require_same(result.operation, name, "the dispatcher attributed the result to another operation")
        self.require(result.duration_ms >= _NOTHING, f"{name} reported a negative duration")
        require_encodable(name, result.value)
        constructs = operation.receiver is Receiver.FACTORY
        self.require(
            (result.created_handle is not None) == constructs,
            f"{name} {'constructs a document but registered no handle' if constructs else 'registered a handle it does not construct'}",
        )
        holds_document = operation.receiver in {Receiver.DOCUMENT, Receiver.FACTORY}
        self.require(
            (result.document is not None) == holds_document,
            f"{name} {'acted on a document but reported no state' if holds_document else 'reported state for a document it never touched'}",
        )

    def test_every_operation_runs_to_a_documented_outcome(self) -> None:
        """All ninety-odd operations are invoked, and each lands where its recipe says."""
        executed: set[str] = set()
        produced_raw: set[str] = set()
        for name in sorted(operation_names()):
            with self.subTest(operation=name):
                outcome = self.session.run_recipe(name, self.session.recipe_context())
                if not outcome.succeeded:
                    failure = outcome.error
                    if failure is None:
                        self.fail(f"{name} neither ran nor failed")
                    recipe = recipe_for(name)
                    self.require(failure.kind in recipe.tolerated, f"{name} was refused with an undeclared {failure.kind} failure")
                    self.require(bool(recipe.note), f"{name} was refused and the table does not say that is allowed")
                    continue
                result = outcome.require()
                self._check_result(name, result)
                executed.add(name)
                if result.raw is not None:
                    produced_raw.add(name)
        refusable = {name for name, recipe in RECIPES.items() if recipe.tolerated}
        self.require_same(
            executed | refusable,
            set(operation_names()),
            "an operation neither ran nor declared that its environment may refuse it",
        )
        self.require_same(
            produced_raw,
            set(raw_capable_operations() & executed),
            "the operations that returned downloadable bytes are not the ones the reference declares binary",
        )


class UserInterfaceReachabilityTests(Assertions, unittest.TestCase):
    """Every operation the browser assets name must still exist."""

    def test_every_manifest_names_only_live_operations(self) -> None:
        """No frontend registry keeps an entry under a name the engine has dropped."""
        catalogued = operation_names()
        for manifest in MANIFESTS:
            with self.subTest(manifest=manifest.label):
                names = manifest.names()
                self.require(len(names) > _NOTHING, f"{manifest.label} yielded no operation names")
                self.require(names <= catalogued, f"{manifest.label} names {sorted(names - catalogued)}")

    def test_the_manifest_scan_reaches_most_of_the_catalogue(self) -> None:
        """The manifests are read, not merely parsed into an empty set."""
        found: set[str] = set()
        for manifest in MANIFESTS:
            found |= manifest.names()
        self.require(len(found) >= _MINIMUM_MANIFEST_NAMES, f"the manifest scan found only {sorted(found)}")

    def test_every_call_site_names_a_live_operation(self) -> None:
        """No module dispatches to an operation name the engine has dropped."""
        catalogued = operation_names()
        references = _call_site_references()
        self.require(bool(references), "no browser module dispatches an operation by literal name")
        found: set[str] = set()
        for module, names in sorted(references.items()):
            with self.subTest(module=module):
                self.require(names <= catalogued, f"{module} dispatches {sorted(names - catalogued)}")
            found |= names
        self.require(len(found) >= _MINIMUM_CALL_SITE_NAMES, f"the call-site scan found only {sorted(found)}")

    def test_the_scanner_reports_a_stale_manifest_entry(self) -> None:
        """A renamed operation left behind in a registry is seen, not skipped."""
        self.require(_STALE_CONTROL not in operation_names(), "the control name is a real operation; choose another")
        source = f"const CONTROL = new Map([\n  ['{_STALE_CONTROL}', renderControl],\n]);\n"
        self.require_same(_pair_keys(_declaration_body(source, _CONTROL_SYMBOL)), frozenset({_STALE_CONTROL}), "a stale entry went unseen")

    def test_the_scanner_reports_a_stale_call_site(self) -> None:
        """A renamed operation left behind at a call site is seen, not skipped."""
        self.require(_STALE_CONTROL not in operation_names(), "the control name is a real operation; choose another")
        found = _call_sites(f"await env.run('{_STALE_CONTROL}', args, handle);")
        self.require_same(found, frozenset({_STALE_CONTROL}), "a stale call site went unseen")

    def test_the_scanner_ignores_shell_command_identifiers(self) -> None:
        """A qualified command name is not mistaken for an operation the engine lacks."""
        self.require_same(_call_sites("this.run('tools.palette');"), frozenset[str](), "a shell command was read as an operation")
        self.require_same(_call_sites("this.openOperation('');"), frozenset[str](), "an empty name was read as an operation")

    def test_the_scanner_skips_a_comment_inside_a_manifest(self) -> None:
        """A commented-out entry is not read as a live registration."""
        source = f"const CONTROL = [\n  // ['{_STALE_CONTROL}', gone],\n  'read',\n];\n"
        found = _all_literals(_declaration_body(source, _CONTROL_SYMBOL))
        self.require_same(found, frozenset({"read"}), "a commented-out entry was read as a live one")

    def test_a_missing_manifest_is_reported(self) -> None:
        """A registry that has been renamed away fails loudly instead of silently."""
        reported = False
        try:
            _declaration_body("const OTHER = [];\n", _CONTROL_SYMBOL)
        except ManifestError:
            reported = True
        self.require(reported, "a manifest that is no longer declared was read without complaint")


def load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None) -> unittest.TestSuite:
    """Order the layers so the cheapest and most fundamental failure reports first.

    Args:
        loader: Loader building the suite.
        tests: Tests already collected from this module.
        pattern: Discovery pattern, unused here.

    Returns:
        unittest.TestSuite: The module's tests, ordered from catalogue outwards.
    """
    del tests, pattern
    suite = unittest.TestSuite()
    for case in (
        CatalogueCompletenessTests,
        RoutingReachabilityTests,
        RecipeTableTests,
        ExecutionCoverageTests,
        UserInterfaceReachabilityTests,
    ):
        suite.addTests(loader.loadTestsFromTestCase(case))
    return suite


if __name__ == "__main__":
    unittest.main()
