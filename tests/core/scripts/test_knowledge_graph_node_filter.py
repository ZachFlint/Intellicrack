#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for the knowledge-graph node-identity filter.

The interactive HTML keeps only nodes whose id starts with ``intellicrack.``.
Module, class, and function nodes must therefore be named by their importable
dotted path (``intellicrack.sample.Sample``) and not by a filesystem-rooted
path (``src.intellicrack.sample.Sample``); otherwise every richly-typed node is
silently dropped and the visualization renders only typeless import targets.

These tests exercise the real generator against real Python source files and
fail loudly if the naming regresses so the filter discards typed nodes again.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest


if TYPE_CHECKING:
    from types import ModuleType


def _load_kg_module() -> ModuleType:
    """Load the knowledge-graph generator script as an importable module.

    The generator lives under ``scripts/knowledge-graph/`` (a hyphenated,
    non-package directory), so it is loaded from its file location rather than
    via a normal import.

    Returns:
        ModuleType: The loaded ``visualize_architecture`` module.

    Raises:
        RuntimeError: If the module spec cannot be created or executed.

    """
    script_path = (
        Path(__file__).resolve().parents[3]
        / "scripts"
        / "knowledge-graph"
        / "visualize_architecture.py"
    )
    spec = importlib.util.spec_from_file_location("kg_visualize_architecture", script_path)
    if spec is None or spec.loader is None:
        msg = f"Could not load spec for {script_path}"
        raise RuntimeError(msg)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _extract_embedded_nodes(html: str) -> list[dict[str, object]]:
    """Return the ``rawNodes`` array embedded in the generated HTML.

    Args:
        html: Full contents of the generated interactive HTML file.

    Returns:
        list[dict[str, object]]: Decoded node records fed to the renderer.

    Raises:
        AssertionError: If the ``rawNodes`` array cannot be located.

    """
    match = re.search(r"const rawNodes=(\[.*?\]);const rawEdges=", html, re.DOTALL)
    assert match is not None, "rawNodes array not found in generated HTML"
    decoded = cast("list[dict[str, object]]", json.loads(match.group(1)))
    assert isinstance(decoded, list)
    return decoded


def _write_sample_package(root: Path) -> None:
    """Create a minimal but real ``src/intellicrack`` package under *root*.

    Args:
        root: Temporary directory that will contain the ``src`` tree.

    """
    pkg = root / "src" / "intellicrack"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text('"""Sample package."""\n', encoding="utf-8")
    (pkg / "helper.py").write_text(
        '"""Helper module used as an import target."""\n\n\ndef assist() -> int:\n    """Return a constant."""\n    return 7\n',
        encoding="utf-8",
    )
    (pkg / "sample.py").write_text(
        '"""Sample module with a class and a function."""\n'
        "\n"
        "import intellicrack.helper\n"
        "\n"
        "\n"
        "class Sample:\n"
        '    """A sample class."""\n'
        "\n"
        "    def method(self) -> int:\n"
        '        """Delegate to the helper."""\n'
        "        return intellicrack.helper.assist()\n"
        "\n"
        "\n"
        "def compute() -> int:\n"
        '    """Compute a value."""\n'
        "    return Sample().method()\n",
        encoding="utf-8",
    )


@pytest.fixture
def generated_nodes(tmp_path: Path) -> list[dict[str, object]]:
    """Build the graph over a real temp package and return the HTML node table.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        list[dict[str, object]]: The node records embedded in the HTML output.

    """
    kg = _load_kg_module()
    _write_sample_package(tmp_path)

    generator = kg.KnowledgeGraphGenerator(tmp_path / "src")
    generator.build_graph()

    out_html = tmp_path / "graph.html"
    generator.generate_interactive_html(
        out_html,
        layout_method="hierarchical",
        dot_output_dir=tmp_path,
    )

    return _extract_embedded_nodes(out_html.read_text(encoding="utf-8"))


def test_typed_nodes_survive_the_filter(generated_nodes: list[dict[str, object]]) -> None:
    """Module, class, and function nodes must appear typed in the HTML.

    Under the pre-fix ``repo_root``-relative naming these are named
    ``src.intellicrack.*`` and dropped by the ``startswith('intellicrack.')``
    filter, leaving only typeless import targets. This asserts the real typed
    nodes are present, so reverting the fix turns the test red.

    Args:
        generated_nodes: Node records embedded in the generated HTML.

    """
    by_id = {str(n["id"]): n for n in generated_nodes}

    assert by_id["intellicrack.sample"]["type"] == "module"
    assert by_id["intellicrack.sample.Sample"]["type"] == "class"
    assert by_id["intellicrack.sample.compute"]["type"] == "function"


def test_import_target_unifies_with_real_module(
    generated_nodes: list[dict[str, object]],
) -> None:
    """An ``import intellicrack.helper`` resolves to the real module node.

    Because file-derived module names now equal importable dotted paths, the
    import edge target and the scanned ``helper.py`` module collapse into one
    typed node rather than a separate typeless stub.

    Args:
        generated_nodes: Node records embedded in the generated HTML.

    """
    by_id = {str(n["id"]): n for n in generated_nodes}

    assert "intellicrack.helper" in by_id
    assert by_id["intellicrack.helper"]["type"] == "module"


def test_no_intellicrack_node_is_typeless(
    generated_nodes: list[dict[str, object]],
) -> None:
    """No internal ``intellicrack.*`` node is rendered as a typeless stub.

    The pre-fix output consisted entirely of ``type == 'unknown'`` import
    targets. Every internal node the generator emits now carries a real type;
    boundary (external-dependency) nodes are the only permitted non-internal
    entries and are excluded from this check.

    Args:
        generated_nodes: Node records embedded in the generated HTML.

    """
    internal = [
        n
        for n in generated_nodes
        if str(n["id"]).startswith("intellicrack.") and n["type"] != "external"
    ]
    assert internal, "no internal intellicrack nodes were emitted"
    typeless = [str(n["id"]) for n in internal if n["type"] == "unknown"]
    assert not typeless, f"typeless internal nodes leaked into output: {typeless}"
