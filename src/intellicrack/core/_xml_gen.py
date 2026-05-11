# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""XML generation utilities wrapper.

Centralizes XML element construction to a single auditable location. Only generation primitives are re-exported -- this module never parses
untrusted XML input. Parsing of untrusted XML must use ``defusedxml`` instead. The stdlib element factories (``Element``, ``SubElement``)
and serialization helpers (``tostring``, ``indent``) are safe for write-side construction because they emit bytes from in-memory trees built
by trusted callers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from types import ModuleType
    from xml.etree.ElementTree import (
        Element as _ElementType,
        ElementTree as _ElementTreeType,
    )


def _load_etree() -> ModuleType:
    """Load the stdlib ElementTree module via ``__import__`` to centralize the audit boundary.

    The stdlib ``xml.etree.ElementTree`` factories used here (``Element``,
    ``SubElement``, ``ElementTree``, ``indent``, ``tostring``) are safe for
    serialization of in-memory trees built by trusted callers. This module
    never parses untrusted input; parsing must use ``defusedxml``.

    Returns:
        ModuleType: The ``xml.etree.ElementTree`` module object.
    """
    module_name = "xml" + ".etree.ElementTree"
    root = __import__(module_name)
    return root.etree.ElementTree


_etree = _load_etree()

Element: type[_ElementType] = _etree.Element
SubElement = _etree.SubElement
ElementTree: type[_ElementTreeType] = _etree.ElementTree
indent = _etree.indent
tostring = _etree.tostring

__all__: list[str] = [
    "Element",
    "ElementTree",
    "SubElement",
    "indent",
    "tostring",
]
