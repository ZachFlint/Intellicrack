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

import ast
import inspect
from pathlib import Path
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
# F-0011: source must use a direct ``import xml.etree.ElementTree`` form
# and must not contain any runtime-obfuscated import or inline suppression.
# ---------------------------------------------------------------------------


def xml_gen_source() -> str:
    """Read the on-disk source of ``xml_gen.py``.

    Returns:
        str: The full source text of the module file.
    """
    module_file = inspect.getfile(xml_gen)
    return Path(module_file).read_text(encoding="utf-8")


def test_f0011_no_importlib_import_module_for_xml_etree() -> None:
    """The module source must not lazily resolve ``xml.etree`` via ``importlib``.

    Regression guard: previous revisions used
    ``importlib.import_module("xml.etree.ElementTree")`` which broke
    static type resolution and obscured the security boundary. This test
    asserts the literal pattern is absent from the file.
    """
    source = xml_gen_source()
    assert "importlib.import_module" not in source, (
        "importlib.import_module must not be used in xml_gen.py (regression: F-0011 -- audit boundary must be statically resolvable)"
    )


def test_f0011_no_importlib_import_for_xml_etree_dotted_path() -> None:
    """No variant of ``import_module`` must reference ``xml.etree``.

    Catches workarounds such as splitting the module name across
    arguments or using ``importlib.import_module(name)`` where ``name``
    is a constructed string variable.
    """
    source = xml_gen_source()
    assert "import_module" not in source, "import_module references must not appear in xml_gen.py"


def test_f0011_no_dunder_import_obfuscation() -> None:
    """The module source must not call ``__import__`` with a constructed name.

    Regression guard for the second-round defect: the original lazy
    ``importlib.import_module`` was swapped for
    ``__import__("xml" + ".etree.ElementTree")`` -- different API,
    same B405-evasion intent. Both are prohibited.
    """
    source = xml_gen_source()
    assert "__import__" not in source, "xml_gen.py must not call __import__ to resolve xml.etree (regression: F-0011 second-round)"


def test_f0011_no_runtime_string_concatenation_of_xml_etree() -> None:
    """Concatenated module names must not appear in the source.

    Both ``"xml" + ".etree"`` and ``"xml.etree" + "."`` are documented
    audit-evasion patterns; either form means a reader cannot grep the
    dependency.
    """
    source = xml_gen_source()
    assert '"xml" +' not in source, "Runtime string-concatenation of xml module name is forbidden"
    assert '"xml.etree" +' not in source, "Runtime string-concatenation of xml.etree submodule name is forbidden"


def test_f0011_uses_direct_import_statement() -> None:
    """The module must import ``xml.etree.ElementTree`` via a real ``import`` statement.

    Parses the source AST and asserts a top-level ``import
    xml.etree.ElementTree`` or ``from xml.etree.ElementTree import ...``
    node exists. This is the positive form of the obfuscation guards
    above.
    """
    tree = ast.parse(xml_gen_source())
    plain_imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    from_imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module is not None}
    assert "xml.etree.ElementTree" in plain_imports | from_imports, (
        "xml_gen.py must contain a direct ``import xml.etree.ElementTree`` or ``from xml.etree.ElementTree import ...`` statement"
    )


def test_f0011_no_inline_suppression_directives() -> None:
    """No inline noqa / nosec / type-ignore directives may live in the file.

    The whole point of the F-0011 remediation is to move the bandit
    B405 exclusion to ``pyproject.toml``. Inline suppressions defeat
    that goal.
    """
    source = xml_gen_source()
    assert "# nosec" not in source, "Inline # nosec directives are forbidden in xml_gen.py"
    assert "# noqa" not in source, "Inline # noqa directives are forbidden in xml_gen.py"
    assert "# type: ignore" not in source, "Inline # type: ignore directives are forbidden in xml_gen.py"
    assert "# pyright: ignore" not in source, "Inline # pyright: ignore directives are forbidden in xml_gen.py"


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
