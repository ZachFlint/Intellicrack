# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
import xml.etree.ElementTree as ET
from typing import Any
from xml.etree.ElementTree import tostring as tostring

Element = ET.Element
ElementTree = ET.ElementTree

def SubElement(parent: ET.Element[Any], tag: str, attrib: dict[str, str] = {}, **extra: str) -> ET.Element:
    """Create an element, append it as the last child of ``parent``, and return it.

    Args:
        parent: Element that receives the new child.
        tag: Tag name of the new element.
        attrib: Attributes of the new element.
        **extra: Further attributes, applied over ``attrib`` where a name appears in both.

    Returns:
        ET.Element: The new child element.
    """

def indent(tree: ET.Element[Any] | ET.ElementTree[Any], space: str = "  ", level: int = 0) -> None:
    """Indent an element tree in place for readable serialization.

    Rewrites the ``text`` and ``tail`` whitespace of every element below the root so each
    element starts on its own line, nested by ``space`` per level. A negative ``level``
    raises ``ValueError``.

    Args:
        tree: Element or element tree to indent.
        space: Whitespace added for each level of nesting.
        level: Nesting level of the root element.
    """

__all__ = ["Element", "ElementTree", "SubElement", "indent", "tostring"]
