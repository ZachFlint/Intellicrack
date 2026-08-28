# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Executable-documentation gate for ``notebooks/hexcore_tutorial.ipynb``.

The tutorial notebook is an assertion-verified walkthrough of every public
method of the Rust-backed :mod:`intellicrack_hexcore` extension: each code
cell exercises the real compiled module against real byte payloads and asserts
the observed behavior. Nothing in the suite executed it, so it silently
drifted from the implementation (the built-in template count grew 48 -> 57 and
the data inspector switched to RFC 5952 compressed IPv6 output) while still
claiming to be verified.

This module closes that gap. It parses the notebook, runs every code cell in
order in a single shared namespace exactly as a Jupyter kernel would, and
fails the moment any embedded assertion breaks -- the compiled cell filename
names the offending cell in the traceback. That makes it a genuine falsifiable
gate against two independent kinds of regression:

* the notebook drifting away from the shipped extension (stale documentation);
* the extension regressing away from its documented, test-vector-backed
  behavior (a real hexcore bug).

The cells share state (later cells reuse names such as ``HELLO_WORLD`` and
modules imported by earlier cells), so they are executed sequentially in one
namespace rather than parametrized independently.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest


if TYPE_CHECKING:
    from collections.abc import Iterator

pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)

_NOTEBOOK_PATH = Path(__file__).resolve().parents[2] / "notebooks" / "hexcore_tutorial.ipynb"


def _load_notebook() -> dict[str, Any]:
    """Load and parse the tutorial notebook JSON document.

    Returns:
        dict[str, Any]: The decoded notebook mapping.
    """
    assert _NOTEBOOK_PATH.is_file(), f"tutorial notebook not found: {_NOTEBOOK_PATH}"
    data = json.loads(_NOTEBOOK_PATH.read_bytes().decode("utf-8"))
    assert isinstance(data, dict), "notebook root is not a JSON object"
    return cast("dict[str, Any]", data)


def _code_cells(notebook: dict[str, Any]) -> Iterator[tuple[int, str]]:
    """Yield ``(index, source)`` for every code cell in document order.

    Args:
        notebook: The decoded notebook mapping.

    Yields:
        tuple[int, str]: The zero-based cell index and its joined source text.
    """
    cells = notebook["cells"]
    assert isinstance(cells, list), "notebook 'cells' is not a list"
    for index, raw_cell in enumerate(cast("list[Any]", cells)):
        if not isinstance(raw_cell, dict):
            continue
        cell = cast("dict[str, Any]", raw_cell)
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source")
        if isinstance(source, str):
            yield index, source
        elif isinstance(source, list):
            yield index, "".join(cast("list[str]", source))


def test_notebook_has_executable_code_cells() -> None:
    """Guard against a vacuous pass: the notebook must carry real code cells."""
    cells = list(_code_cells(_load_notebook()))
    assert len(cells) >= 30, f"expected a substantial tutorial, found {len(cells)} code cells"
    assert all(text.strip() for _, text in cells), "a code cell is empty"


def test_tutorial_notebook_every_cell_passes() -> None:
    """Execute every notebook code cell against the live extension in order.

    Each cell's embedded assertions verify real :mod:`intellicrack_hexcore`
    behavior (hash test vectors, transform round-trips, template inventory,
    inspector output, patch formats, and error paths). Any drift or regression
    raises out of the executed cell, failing this test; the compiled cell
    filename identifies the offending cell in the traceback.
    """
    namespace: dict[str, object] = {}
    executed = 0
    for index, source in _code_cells(_load_notebook()):
        code = compile(source, f"<hexcore_tutorial cell {index}>", "exec")
        exec(code, namespace)
        executed += 1
    assert executed >= 30, f"only {executed} cells executed"
