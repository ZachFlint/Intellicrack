# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit3 U10 regression tests for ``intellicrack.core.xml_gen``.

Covers:

- F-0011: ``xml_gen.py`` must not obfuscate its
  ``xml.etree.ElementTree`` dependency. Earlier revisions used
  :func:`importlib.import_module` and later
  ``__import__("xml" + ".etree.ElementTree")`` purely to dodge bandit
  B405. Both forms broke static analysers and type checkers. The
  production fix uses a plain ``import xml.etree.ElementTree as ET``
  with the B405 skip recorded once in ``pyproject.toml`` instead of
  scattered inline directives.
"""

from __future__ import annotations

from xml.etree.ElementTree import (
    Element as _StdlibElement,
    ElementTree as _StdlibElementTree,
    SubElement as _stdlib_SubElement,
    indent as _stdlib_indent,
    tostring as _stdlib_tostring,
)

from intellicrack.core import xml_gen
from intellicrack.core.xml_gen import (
    Element,
    ElementTree,
    SubElement,
    indent,
    tostring,
)


# ---------------------------------------------------------------------------
# F-0011: the re-exported XML primitives must be the genuine, fully functional
# stdlib ``xml.etree.ElementTree`` objects. The behavioural property that
# matters -- regardless of how the import is spelled in source -- is that the
# module's factories produce byte-for-byte identical XML to the stdlib
# originals imported directly. These gates drive the production re-exports
# end-to-end and compare against an independent oracle: the same operation
# performed with the directly-imported stdlib objects.
# ---------------------------------------------------------------------------


def test_f0011_element_factory_matches_stdlib_element() -> None:
    """``xml_gen.Element`` must build a tree whose serialization equals the stdlib oracle.

    Oracle: construct the identical tree with the directly-imported stdlib
    ``Element``/``SubElement`` and serialize both. A re-export that wrapped
    or replaced ``Element`` with a subclass altering ``tag``/child handling
    would diverge from the stdlib bytes and fail.
    """
    produced_root = xml_gen.Element("Configuration", {"id": "vm-1"})
    xml_gen.SubElement(produced_root, "Memory").text = "4096"
    produced = _stdlib_tostring(produced_root, encoding="unicode")

    oracle_root = _StdlibElement("Configuration", {"id": "vm-1"})
    _stdlib_SubElement(oracle_root, "Memory").text = "4096"
    oracle = _stdlib_tostring(oracle_root, encoding="unicode")

    assert produced == oracle == '<Configuration id="vm-1"><Memory>4096</Memory></Configuration>'
    assert type(produced_root) is _StdlibElement


def test_f0011_subelement_links_into_stdlib_tree() -> None:
    """``xml_gen.SubElement`` must attach children exactly as the stdlib oracle does.

    Oracle: the directly-imported stdlib ``SubElement`` on an equivalent
    tree. Falsifiable: a wrapper that failed to append the child, or
    appended in a different order, would not match the stdlib byte stream.
    """
    produced_root = _StdlibElement("Networking")
    produced_child = xml_gen.SubElement(produced_root, "DefaultSwitch")
    produced_child.text = "True"
    xml_gen.SubElement(produced_root, "MacAddress").text = "00-15-5D-00-00-01"

    oracle_root = _StdlibElement("Networking")
    _stdlib_SubElement(oracle_root, "DefaultSwitch").text = "True"
    _stdlib_SubElement(oracle_root, "MacAddress").text = "00-15-5D-00-00-01"

    assert next(iter(produced_root)) is produced_child
    assert _stdlib_tostring(produced_root, encoding="unicode") == _stdlib_tostring(oracle_root, encoding="unicode")
    assert type(produced_child) is _StdlibElement


def test_f0011_indent_matches_stdlib_indent() -> None:
    """``xml_gen.indent`` must apply whitespace identically to the stdlib oracle.

    Oracle: ``xml.etree.ElementTree.indent`` imported directly on an
    equivalent tree. Falsifiable: a re-export pointing at a different
    indenter (or a no-op) would produce different whitespace than the
    stdlib oracle and fail the byte comparison.
    """
    produced_root = _StdlibElement("root")
    _stdlib_SubElement(produced_root, "child").text = "value"
    xml_gen.indent(_StdlibElementTree(produced_root), space="    ")

    oracle_root = _StdlibElement("root")
    _stdlib_SubElement(oracle_root, "child").text = "value"
    _stdlib_indent(_StdlibElementTree(oracle_root), space="    ")

    produced = _stdlib_tostring(produced_root, encoding="unicode")
    assert produced == _stdlib_tostring(oracle_root, encoding="unicode")
    assert produced == "<root>\n    <child>value</child>\n</root>"


def test_f0011_tostring_matches_stdlib_tostring() -> None:
    """``xml_gen.tostring`` must serialize identically to the stdlib oracle.

    Oracle: ``xml.etree.ElementTree.tostring`` imported directly. Both the
    unicode and the default bytes encodings are checked so a re-export that
    swapped the serializer or changed the default encoding would fail.
    """
    root = _StdlibElement("Configuration")
    _stdlib_SubElement(root, "vGPU").text = "Enable"

    produced_unicode = xml_gen.tostring(root, encoding="unicode")
    produced_bytes = xml_gen.tostring(root)

    assert produced_unicode == _stdlib_tostring(root, encoding="unicode")
    assert produced_bytes == _stdlib_tostring(root)
    assert produced_unicode == "<Configuration><vGPU>Enable</vGPU></Configuration>"
    assert produced_bytes == b"<Configuration><vGPU>Enable</vGPU></Configuration>"


def test_f0011_elementtree_wraps_root_like_stdlib() -> None:
    """``xml_gen.ElementTree`` must wrap a root element exactly as the stdlib oracle.

    Oracle: ``xml.etree.ElementTree.ElementTree`` imported directly. The
    constructed tree's ``getroot()`` must return the supplied element and
    its serialization must match the stdlib-built tree byte-for-byte.
    """
    root = _StdlibElement("Configuration")
    _stdlib_SubElement(root, "Memory").text = "2048"

    produced_tree = xml_gen.ElementTree(root)
    oracle_tree = _StdlibElementTree(root)

    assert produced_tree.getroot() is root
    produced_root_elem = produced_tree.getroot()
    oracle_root_elem = oracle_tree.getroot()
    assert produced_root_elem is not None
    assert oracle_root_elem is not None
    assert _stdlib_tostring(produced_root_elem, encoding="unicode") == _stdlib_tostring(oracle_root_elem, encoding="unicode")
    assert type(produced_tree) is _StdlibElementTree


def test_f0011_re_exports_are_the_stdlib_objects() -> None:
    """Re-exported names must be identity-equal to the stdlib originals.

    Defends against accidental wrapping that would silently change
    behaviour (e.g. swapping ``Element`` for a custom subclass).
    """
    assert xml_gen.Element is _StdlibElement
    assert xml_gen.SubElement is _stdlib_SubElement
    assert xml_gen.ElementTree is _StdlibElementTree
    assert xml_gen.indent is _stdlib_indent
    assert xml_gen.tostring is _stdlib_tostring


# ---------------------------------------------------------------------------
# Functional surface: re-exports must remain operational after the refactor
# ---------------------------------------------------------------------------


def test_xml_gen_exports_match_dunder_all() -> None:
    """The module ``__all__`` must list exactly the supported re-exports."""
    assert set(xml_gen.__all__) == {
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


def test_xml_gen_representative_sandbox_xml_payload() -> None:
    """A representative sandbox-config XML payload must round-trip through tostring.

    Mirrors the shape of XML the ``intellicrack.sandbox.windows`` module
    builds with these factories: nested ``Configuration`` element with
    ``Memory`` and ``vGPU`` children, then serialised with deterministic
    indent.
    """
    configuration = Element("Configuration")
    memory = SubElement(configuration, "Memory")
    memory.text = "4096"
    vgpu = SubElement(configuration, "vGPU")
    vgpu.text = "Enable"
    networking = SubElement(configuration, "Networking")
    SubElement(networking, "DefaultSwitch").text = "True"

    tree = ElementTree(configuration)
    indent(tree, space="  ")
    payload = tostring(configuration, encoding="unicode")

    assert "<Configuration>" in payload
    assert "<Memory>4096</Memory>" in payload
    assert "<vGPU>Enable</vGPU>" in payload
    assert "<DefaultSwitch>True</DefaultSwitch>" in payload
    assert payload.endswith("</Configuration>")
