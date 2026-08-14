# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The hexbench test suite.

The suite lives inside the package it tests so that deleting ``src/hexbench``
removes the tests with it and cannot break anything else in the repository. It
is written against :mod:`unittest` rather than pytest for the same reason: the
repository's pytest configuration points at a different tree and loads plugins
this package must not depend on, while :mod:`unittest` is stdlib and couples to
nothing.

Run the whole suite from the repository root::

    pixi run python -m unittest discover -s src/hexbench/tests -t src -v

Three conventions apply to every module here, each of them forced by a quality
gate rather than by taste:

* **Import the shared scaffolding relatively.** ``from ._support import ...``
  and ``from ._recipes import ...``. The absolute spelling
  ``from hexbench.tests._support import ...`` trips ruff's ``PLC2701``, and the
  root ``per-file-ignores`` entry for ``tests/**`` does not reach this
  directory.
* **Assert through the shared vocabulary in**
  :class:`hexbench.tests._support.Assertions`, which every case in the package
  inherits: ``self.equal``, ``self.unequal``, ``self.truthy``, ``self.falsy``,
  ``self.contains``, ``self.absent``, ``self.is_none``, ``self.exceeds``,
  ``self.raises``, ``self.refusal``, ``self.require`` and
  ``self.require_same``, or the ``require_*`` functions they are built from.
  Neither of the two obvious spellings is available here: a bare ``assert``
  trips ruff's ``S101`` and ``self.assertEqual`` trips ``PT009``, because the
  ``per-file-ignores`` entry that relaxes both is scoped to the repository's
  own ``tests/`` tree and does not reach this directory. Aliasing the bound
  method to dodge the rule would be a suppression in all but spelling, so the
  helpers are ordinary functions raising :class:`AssertionError`, which is
  precisely what ``unittest`` reports as a failure. Define no new assertion
  helper in a test module: add it to ``_support`` so there is one of it.
* **Bring no third-party dependency.** Only the standard library and
  ``intellicrack_hexcore`` may be imported, exactly as in the rest of hexbench.

:mod:`hexbench.tests._support` holds the fixtures: temporary directories, real
binaries copied out of the running installation, and an in-process
:class:`~hexbench.api.Application` that answers requests without a socket.
:mod:`hexbench.tests._recipes` holds one invocation recipe per catalogued
operation, which is what lets a coverage test fail loudly when the Rust crate
grows a method nothing exercises.
"""
