# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Checking that the dependency scan reads the package it claims to read.

The scan drives ``just update``: what it reports is what gets upgraded, and
what it fails to report is what a fresh install will be missing. So these tests
run it against the real package and the real manifest and insist on the three
findings that are easy to lose.

The toolkit is the first. It is imported by name through ``importlib``, so no
import statement mentions it and a scanner that only walked import statements
would miss the one dependency the window needs. The freezer is the second: it
appears solely in the build description, so finding it proves that file is
being read too. The engine is the third, and the interesting thing about it is
that it must be reported as *undeclared* -- it is built here rather than
resolved from an index -- without being reported as a gap.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Final

import hexbench
from hexbench.dependencies import Dependency, declared_distributions, imported_names, scan, source_files, third_party
from hexbench.tests._support import Assertions, scratch_directory
from hexbench.window import TOOLKIT_MODULE


_PACKAGE_ROOT: Final = Path(hexbench.__file__).resolve().parent
_MANIFEST: Final = _PACKAGE_ROOT.parents[1] / "pyproject.toml"

_ENGINE: Final = "intellicrack-hexcore"
_FREEZER: Final = "pyinstaller"
_TOOLKIT_DISTRIBUTION: Final = "pywebview"
_SPEC_NAME: Final = "hexbench.spec"
_MANIFEST_NAME: Final = "pyproject.toml"

_SYNTHETIC_MANIFEST: Final = """
[tool.pixi]
dependencies.python = "3.13.*"
dependencies.conda-only-name = "*"
pypi-dependencies.top-level-name = ">=1, <2"

[tool.pixi.feature.build.pypi-dependencies]
Feature_Only_Name = ">=6, <7"

[tool.pixi.feature.test.dependencies]
feature-conda-name = "*"
"""


def _declared_in(body: str) -> set[str]:
    """Read the declarations out of a manifest written for one test.

    Args:
        body: The manifest text to write and then scan.

    Returns:
        set[str]: The distributions the scanner reports as declared.
    """
    with scratch_directory() as directory:
        manifest = directory / _MANIFEST_NAME
        manifest.write_text(body, encoding="utf-8")
        return declared_distributions(manifest)


def _find(dependencies: tuple[Dependency, ...], distribution: str) -> Dependency | None:
    """Pick one dependency out of a scan by name.

    Args:
        dependencies: What the scan reported.
        distribution: Distribution to look for.

    Returns:
        Dependency | None: The matching entry, or ``None`` if it is absent.
    """
    return next((entry for entry in dependencies if entry.distribution == distribution), None)


class ScanTests(Assertions, unittest.TestCase):
    """The scan of the real package finds what the package really needs."""

    report = scan(_PACKAGE_ROOT, _MANIFEST)

    def test_the_manifest_being_scanned_exists(self) -> None:
        """The paths these tests derive point at the real files."""
        self.truthy(_MANIFEST.is_file(), f"the manifest at {_MANIFEST}")
        self.truthy((_PACKAGE_ROOT / _SPEC_NAME).is_file(), f"the build description at {_PACKAGE_ROOT / _SPEC_NAME}")

    def test_the_dynamically_imported_toolkit_is_found(self) -> None:
        """The toolkit no import statement names is still reported."""
        self.contains(TOOLKIT_MODULE, self.report.modules, "the modules the scan found")
        entry = _find(self.report.dependencies, _TOOLKIT_DISTRIBUTION)
        self.unequal(entry, None, f"the {_TOOLKIT_DISTRIBUTION} entry in the scan")
        if entry is not None:
            self.truthy(entry.declared, f"whether {_TOOLKIT_DISTRIBUTION} is declared in the manifest")

    def test_the_build_description_is_scanned(self) -> None:
        """The freezer, named only in the spec file, is reported."""
        entry = _find(self.report.dependencies, _FREEZER)
        self.unequal(entry, None, f"the {_FREEZER} entry, which only the spec file can produce")
        if entry is not None:
            self.truthy(entry.declared, f"whether {_FREEZER} is declared in the manifest")

    def test_the_engine_is_undeclared_but_not_a_gap(self) -> None:
        """The locally built engine is distinguished from a missing declaration."""
        entry = _find(self.report.dependencies, _ENGINE)
        self.unequal(entry, None, f"the {_ENGINE} entry in the scan")
        if entry is not None:
            self.falsy(entry.declared, f"whether {_ENGINE} is resolved from an index")
            self.truthy(entry.built_here, f"whether {_ENGINE} is built from this repository")

    def test_nothing_is_both_declared_and_built_here(self) -> None:
        """The two ways of getting a dependency stay distinct."""
        confused = sorted(entry.distribution for entry in self.report.dependencies if entry.declared and entry.built_here)
        self.require_same(confused, [], "these are reported as both declared and built here")

    def test_the_package_does_not_depend_on_itself(self) -> None:
        """Its own modules are not mistaken for third-party ones."""
        self.absent("hexbench", self.report.modules, "the modules the scan found")

    def test_the_standard_library_is_not_a_dependency(self) -> None:
        """Modules that ship with Python are not reported for upgrading."""
        for name in ("ast", "json", "pathlib", "unittest", "tomllib"):
            with self.subTest(module=name):
                self.absent(name, self.report.modules, "the modules the scan found")

    def test_every_reported_module_belongs_to_a_dependency(self) -> None:
        """Nothing found by the scan is dropped before it reaches the caller."""
        attributed = {name for entry in self.report.dependencies for name in entry.imported_as}
        self.require_same(sorted(set(self.report.modules) - attributed), [], "these modules were found but attributed to nothing")


class SourceReadingTests(Assertions, unittest.TestCase):
    """The pieces the scan is built from behave on real input."""

    def test_both_source_kinds_are_collected(self) -> None:
        """Modules and the build description are both read."""
        collected = source_files(_PACKAGE_ROOT)
        suffixes = {path.suffix for path in collected}
        self.contains(".py", sorted(suffixes), "the file kinds the scan reads")
        self.contains(".spec", sorted(suffixes), "the file kinds the scan reads")
        self.contains(_PACKAGE_ROOT / _SPEC_NAME, collected, "the collected files")

    def test_import_forms_are_all_recognised(self) -> None:
        """Every spelling of an import reduces to its top-level module."""
        source = _PACKAGE_ROOT / "tests" / "test_dependencies.py"
        names = imported_names([source])
        self.contains("hexbench", sorted(names), "the imports of this very test module")
        self.contains("unittest", sorted(names), "the imports of this very test module")
        self.contains("pathlib", sorted(names), "the imports of this very test module")

    def test_relative_imports_are_not_treated_as_packages(self) -> None:
        """A dotted-leading import names nothing that could be upgraded."""
        source = _PACKAGE_ROOT / "dependencies.py"
        names = imported_names([source])
        self.absent("", sorted(names), "the imports of the scanner")
        self.contains("hexbench", sorted(names), "the imports of the scanner")

    def test_third_party_keeps_only_outside_names(self) -> None:
        """Filtering removes this package and the standard library, and no more."""
        self.require_same(sorted(third_party(["ast", "hexbench", "webview", "sys"])), ["webview"], "what survives filtering")

    def test_the_manifest_declares_the_toolkit(self) -> None:
        """The declared set is read from the real manifest, not assumed."""
        declared = declared_distributions(_MANIFEST)
        self.contains(_TOOLKIT_DISTRIBUTION, sorted(declared), "the distributions the manifest declares")
        self.contains(_FREEZER, sorted(declared), "the distributions the manifest declares")


class ManifestReadingTests(Assertions, unittest.TestCase):
    """Every table pixi resolves from an index counts as a declaration."""

    declared = _declared_in(_SYNTHETIC_MANIFEST)

    def test_a_top_level_declaration_is_read(self) -> None:
        """The table outside any feature is still read."""
        self.contains("top-level-name", sorted(self.declared), "the declarations found in the manifest")

    def test_a_feature_declaration_is_read(self) -> None:
        """A name declared only under a feature is not reported as a gap."""
        self.contains("feature-only-name", sorted(self.declared), "the declarations found in the manifest")

    def test_conda_dependencies_are_not_declarations(self) -> None:
        """Only the index tables count, so conda packages stay out."""
        for name in ("conda-only-name", "feature-conda-name"):
            with self.subTest(distribution=name):
                self.absent(name, sorted(self.declared), "the declarations found in the manifest")


if __name__ == "__main__":
    unittest.main()
