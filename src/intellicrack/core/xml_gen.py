# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""XML generation utilities wrapper.

Centralizes XML element construction to a single auditable location. Only generation primitives are re-exported -- this module never parses
untrusted XML input. Parsing of untrusted XML must use ``defusedxml`` instead. The stdlib element factories (``Element``, ``SubElement``)
and serialization helpers (``tostring``, ``indent``) are safe for write-side construction because they emit bytes from in-memory trees built
by trusted callers.

The ``defusedxml`` package does not provide a hardened replacement for write-side ElementTree construction; its scope is parser hardening
only. Write-side use of :mod:`xml.etree.ElementTree` is therefore the correct stdlib API. The bandit B405 finding for the direct import is
suppressed project-wide via ``pyproject.toml`` ``[tool.bandit] skips``, not via inline comments or runtime obfuscation.
"""

from __future__ import annotations

from xml.etree.ElementTree import Element, ElementTree, SubElement, indent, tostring


__all__: list[str] = [
    "Element",
    "ElementTree",
    "SubElement",
    "indent",
    "tostring",
]
