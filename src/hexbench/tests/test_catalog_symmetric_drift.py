# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""``build_catalog`` must catch a stub entry that has no live counterpart, not just the reverse.

The module promises that "any drift between the compiled module and its stub
is reported as an error instead of silently narrowing what the harness can
reach." Before this fix, ``build_catalog`` only ever walked the *live*
names (``runtime_surface()``) and asked whether each had a stub entry; a name
removed from the compiled extension while ``__init__.pyi`` still declared it
was never visited at all, so it vanished from the catalogue with zero
``CatalogError``. This case reproduces exactly that shape with a fully
synthetic runtime surface and stub, so it does not depend on -- or risk
disturbing -- the real compiled extension's actual API.
"""

from __future__ import annotations

import contextlib
import unittest
from typing import TYPE_CHECKING

from hexbench import catalog
from hexbench.tests._support import Assertions


if TYPE_CHECKING:
    from collections.abc import Generator


@contextlib.contextmanager
def _replaced_attribute(owner: object, name: str, replacement: object) -> Generator[None]:
    """Swap one attribute of ``owner`` for the duration of a ``with`` block.

    Args:
        owner: Module or class whose attribute is swapped.
        name: Attribute to swap.
        replacement: Value the attribute holds inside the block.

    Yields:
        None: Control, with the replacement installed; the original is restored on exit.
    """
    original = getattr(owner, name)
    setattr(owner, name, replacement)
    try:
        yield
    finally:
        setattr(owner, name, original)


class SymmetricDriftDetectionTests(Assertions, unittest.TestCase):
    """A stub entry with no live counterpart must fail the catalogue build."""

    def test_a_stub_only_operation_raises_catalog_error(self) -> None:
        """A method present in the stub but removed from the compiled module must be reported, not dropped silently.

        ``length`` is a real, argument-free method on the compiled
        ``HexDocument`` class, so if the new symmetric check is missing this
        does not blow up on an unrelated ``AttributeError`` while building the
        one genuine operation -- it falls straight through to a clean, normal
        return, which is exactly what the old code did with a stale stub entry.
        """
        synthetic_signatures: dict[str, tuple[list[tuple[str, str]], str]] = {
            "length": ([], "int"),
            "removed_from_the_crate": ([], "None"),
        }

        def _synthetic_stub_signatures() -> dict[str, tuple[list[tuple[str, str]], str]]:
            """Describe a stub that still declares an operation the crate no longer has.

            Returns:
                dict[str, tuple[list[tuple[str, str]], str]]: The synthetic stub signatures.
            """
            return synthetic_signatures

        def _synthetic_runtime_surface() -> tuple[frozenset[str], frozenset[str]]:
            """Describe a compiled module that only exposes ``length``.

            Returns:
                tuple[frozenset[str], frozenset[str]]: The synthetic live method and property names.
            """
            return frozenset({"length"}), frozenset()

        catalog.build_catalog.cache_clear()
        try:
            with (
                _replaced_attribute(catalog, "_stub_signatures", _synthetic_stub_signatures),
                _replaced_attribute(catalog, "runtime_surface", _synthetic_runtime_surface),
            ):
                self.raises(
                    catalog.CatalogError,
                    "a stub entry with no live counterpart",
                    catalog.build_catalog,
                )
        finally:
            catalog.build_catalog.cache_clear()

    def test_the_real_catalogue_still_builds_with_no_stub_only_drift(self) -> None:
        """The real compiled module and its real stub must build cleanly, with no false positive from the new check."""
        catalog.build_catalog.cache_clear()
        try:
            operations = catalog.build_catalog()
        finally:
            catalog.build_catalog.cache_clear()
        self.require(len(operations) > 0, "the real catalogue built with no catalogued operations at all")


if __name__ == "__main__":
    unittest.main()
