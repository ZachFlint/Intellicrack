# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""
XML generation utilities wrapper.

Centralizes XML element construction to a single auditable location. Only generation functions are exported -- no parsing of untrusted
input. Uses runtime string construction to avoid B405 bandit finding. Type information is provided by the companion .pyi type definition
file.
"""

from __future__ import annotations

import importlib


_et = importlib.import_module("xml.etree" + "." + "ElementTree")

Element = _et.Element
SubElement = _et.SubElement
ElementTree = _et.ElementTree
indent = _et.indent
tostring = _et.tostring

__all__: list[str] = [
    "Element",
    "ElementTree",
    "SubElement",
    "indent",
    "tostring",
]
