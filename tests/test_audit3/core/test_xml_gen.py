# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit3 U10 tests for ``intellicrack.core._xml_gen`` remediation.

Validates F-0011 - the obfuscated ``importlib.import_module("xml.etree" +
"." + "ElementTree")`` indirection has been replaced with a direct,
auditable import. The tests assert both that the obfuscation marker is
gone from the source file and that the re-exported XML primitives still
behave as ``xml.etree.ElementTree``'s public API.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from intellicrack.core import _xml_gen


_XML_GEN_SOURCE: Path = Path(_xml_gen.__file__).resolve()


class TestSourceHasNoObfuscation:
    """F-0011: the runtime import-string assembly trick must be removed."""

    def test_no_import_module_call(self) -> None:
        """``importlib.import_module`` must not appear in the source."""
        source = _XML_GEN_SOURCE.read_text(encoding="utf-8")
        assert "import_module" not in source

    def test_no_runtime_string_concatenation_for_xml(self) -> None:
        """The ``"xml.etree" + "."`` concatenation must not appear."""
        source = _XML_GEN_SOURCE.read_text(encoding="utf-8")
        assert '"xml.etree" + "."' not in source
        assert "'xml.etree' + '.'" not in source

    def test_imports_xml_etree_directly(self) -> None:
        """The replacement import must be a plain ``from xml.etree import ElementTree``."""
        source = _XML_GEN_SOURCE.read_text(encoding="utf-8")
        assert "from xml.etree import ElementTree as ET" in source

    def test_no_b405_evasion_comment(self) -> None:
        """Any docstring text that admits to evading B405 must be gone."""
        source = _XML_GEN_SOURCE.read_text(encoding="utf-8")
        assert "to avoid B405" not in source
        assert "evade" not in source.lower()


class TestReExportedSymbolsRemainCallable:
    """The five generation primitives must still be the real stdlib callables."""

    def test_element_factory_callable(self) -> None:
        """``Element("tag")`` produces a usable element instance."""
        elem = _xml_gen.Element("root")
        assert elem.tag == "root"

    def test_subelement_factory_callable(self) -> None:
        """``SubElement(parent, "child")`` attaches a child element."""
        root = _xml_gen.Element("root")
        child = _xml_gen.SubElement(root, "child")
        assert child.tag == "child"
        assert list(root) == [child]

    def test_indent_callable(self) -> None:
        """``indent`` mutates the tree to add whitespace between elements."""
        root = _xml_gen.Element("root")
        _xml_gen.SubElement(root, "child")
        _xml_gen.indent(root, space="  ")
        assert root.text is not None
        assert "\n" in root.text

    def test_tostring_callable_returns_bytes(self) -> None:
        """``tostring`` serialises the element back to ``bytes``."""
        root = _xml_gen.Element("root")
        _xml_gen.SubElement(root, "child").text = "value"
        rendered = _xml_gen.tostring(root, encoding="utf-8")
        assert isinstance(rendered, bytes)
        assert b"<root>" in rendered
        assert b"<child>value</child>" in rendered

    def test_elementtree_class_constructible(self) -> None:
        """``ElementTree(element)`` wraps the element in a serialisable tree."""
        root = _xml_gen.Element("root")
        tree = _xml_gen.ElementTree(root)
        assert tree.getroot() is root


class TestSymbolsAreStdlibObjects:
    """The re-exports must originate from the stdlib ``xml.etree`` modules.

    ``xml.etree.ElementTree`` accelerates several primitives by reassigning
    them to the C ``_elementtree`` extension at import time, so the
    ``__module__`` attribute can be either ``"xml.etree.ElementTree"`` (pure
    Python fallback) or ``"_elementtree"`` (C accelerator) depending on the
    interpreter build.
    """

    _STDLIB_MODULES: tuple[str, ...] = ("xml.etree.ElementTree", "_elementtree")

    def test_element_module_is_stdlib(self) -> None:
        """``_xml_gen.Element`` originates from ``xml.etree.ElementTree``."""
        assert _xml_gen.Element.__module__ in self._STDLIB_MODULES

    def test_subelement_module_is_stdlib(self) -> None:
        """``_xml_gen.SubElement`` originates from ``xml.etree.ElementTree``."""
        assert _xml_gen.SubElement.__module__ in self._STDLIB_MODULES

    def test_tostring_module_is_stdlib(self) -> None:
        """``_xml_gen.tostring`` originates from ``xml.etree.ElementTree``."""
        assert _xml_gen.tostring.__module__ in self._STDLIB_MODULES

    def test_elementtree_module_is_stdlib(self) -> None:
        """``_xml_gen.ElementTree`` originates from ``xml.etree.ElementTree``."""
        assert _xml_gen.ElementTree.__module__ in self._STDLIB_MODULES


class TestPyiStubRemoved:
    """The companion ``.pyi`` stub is no longer needed once the import is direct."""

    def test_pyi_stub_absent(self) -> None:
        """``_xml_gen.pyi`` should be absent now that types come from the real import."""
        pyi_path = _XML_GEN_SOURCE.with_suffix(".pyi")
        assert not pyi_path.exists(), (
            f"Expected no .pyi stub at {pyi_path}; the .py file's direct import provides types"
        )


@pytest.mark.parametrize("symbol", ["Element", "SubElement", "ElementTree", "indent", "tostring"])
def test_all_symbols_in_dunder_all(symbol: str) -> None:
    """Every documented re-export appears in ``__all__``.

    Args:
        symbol: Name of the re-exported XML primitive.
    """
    assert symbol in _xml_gen.__all__
