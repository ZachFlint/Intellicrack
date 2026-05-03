# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""XML generation utilities wrapper.

Centralizes XML element construction to a single auditable location. Only generation primitives are re-exported -- this module never parses
untrusted XML input. Parsing of untrusted XML must use ``defusedxml`` instead. The stdlib element factories (``Element``, ``SubElement``)
and serialization helpers (``tostring``, ``indent``) are safe for write-side construction because they emit bytes from in-memory trees
built by trusted callers.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET


Element = ET.Element
SubElement = ET.SubElement
ElementTree = ET.ElementTree
indent = ET.indent
tostring = ET.tostring

__all__: list[str] = [
    "Element",
    "ElementTree",
    "SubElement",
    "indent",
    "tostring",
]
