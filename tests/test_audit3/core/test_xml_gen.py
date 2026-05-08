# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit3 U10 regression tests for ``intellicrack.core._xml_gen``.

Covers:

- F-0011: ``_xml_gen.py`` must not use :func:`importlib.import_module`
  to resolve the ``xml.etree.ElementTree`` module. The previous
  implementation lazily imported the module via ``importlib`` which made
  static analysers, basedpyright, and security scanners unable to track
  the dependency. The fix loads the module via a direct call so the
  audit boundary is grep-able.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from intellicrack.core import _xml_gen
from intellicrack.core._xml_gen import Element, ElementTree, SubElement, indent, tostring


# ---------------------------------------------------------------------------
# F-0011: source must contain no ``importlib.import_module`` for xml etree
# ---------------------------------------------------------------------------


def _xml_gen_source() -> str:
    """Read the on-disk source of ``_xml_gen.py``.

    Returns:
        str: The full source text of the module file.
    """
    module_file = inspect.getfile(_xml_gen)
    return Path(module_file).read_text(encoding="utf-8")


def test_f0011_no_importlib_import_module_for_xml_etree() -> None:
    """The module source must not lazily resolve ``xml.etree`` via ``importlib``.

    Regression guard: previous revisions used
    ``importlib.import_module("xml.etree.ElementTree")`` which broke
    static type resolution and obscured the security boundary. This test
    asserts the literal pattern is absent from the file.
    """
    source = _xml_gen_source()
    assert "importlib.import_module" not in source, (
        "importlib.import_module must not be used in _xml_gen.py (regression: F-0011 -- audit boundary must be statically resolvable)"
    )


def test_f0011_no_importlib_import_for_xml_etree_dotted_path() -> None:
    """No variant of ``import_module`` must reference ``xml.etree``.

    Catches workarounds such as splitting the module name across
    arguments or using ``importlib.import_module(name)`` where ``name``
    is a constructed string variable.
    """
    source = _xml_gen_source()
    assert "import_module" not in source, "import_module references must not appear in _xml_gen.py"


# ---------------------------------------------------------------------------
# Functional surface: re-exports must remain operational after the refactor
# ---------------------------------------------------------------------------


def test_xml_gen_exports_match_dunder_all() -> None:
    """The module ``__all__`` must list exactly the supported re-exports."""
    assert set(_xml_gen.__all__) == {
        "Element",
        "ElementTree",
        "SubElement",
        "indent",
        "tostring",
    }


def test_xml_gen_element_factory_constructs_element() -> None:
    """``Element`` must construct a working ElementTree element."""
    root = Element("Configuration")
    assert root.tag == "Configuration"
    assert list(root) == []


def test_xml_gen_subelement_appends_child() -> None:
    """``SubElement`` must append a child to its parent."""
    root = Element("Configuration")
    child = SubElement(root, "Memory")
    child.text = "4096"
    first_child = next(iter(root))
    assert first_child is child
    assert first_child.text == "4096"


def test_xml_gen_indent_inserts_whitespace() -> None:
    """``indent`` must add deterministic whitespace to a built tree."""
    root = Element("root")
    SubElement(root, "child").text = "value"
    tree = ElementTree(root)
    indent(tree, space="  ")
    serialized = tostring(root, encoding="unicode")
    assert "\n  <child>" in serialized


def test_xml_gen_tostring_round_trip() -> None:
    """``tostring`` must produce well-formed XML for an in-memory tree."""
    root = Element("Configuration")
    SubElement(root, "vGPU").text = "Enable"
    payload = tostring(root, encoding="unicode")
    assert payload.startswith("<Configuration>")
    assert "<vGPU>Enable</vGPU>" in payload
    assert payload.endswith("</Configuration>")
