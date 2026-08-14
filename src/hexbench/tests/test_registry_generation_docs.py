# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The registry module must not claim its bookkeeping counter is the byte-window one.

:class:`~hexbench.registry.DocumentSlot` keeps its own bookkeeping generation
counter, bumped by :meth:`~hexbench.registry.DocumentSlot.bump` after *any*
mutating operation the dispatcher runs -- a bookmark edit exactly as much as a
byte edit. The engine's own content generation counter
(``HexDocument.generation()``, surfaced through ``read_window``) is a
different number, advanced only when the bytes underneath actually change. The
module used to document the two as one and the same, which is false: a client
that trusted that claim would compare numbers that are allowed to drift apart
the moment a bookmark, template, VA mapping or save touches the document.

This case does not re-litigate whether the two counters should be unified --
they deliberately are not -- only that the module's own words stop making a
promise the code does not keep.
"""

from __future__ import annotations

import unittest

from hexbench import registry
from hexbench.tests._support import Assertions


class RegistryModuleDocstringTests(Assertions, unittest.TestCase):
    """The module docstring's description of the two generation counters."""

    def test_module_docstring_does_not_pair_byte_windows_with_the_slot_counter(self) -> None:
        """The old false claim that clients cache windows against the slot's own counter must be gone."""
        doc = registry.__doc__ or ""
        self.require(doc, "hexbench.registry carries no module docstring to check")
        self.require(
            "Clients cache decoded byte windows against ``(handle, generation)``" not in doc,
            "the module docstring still claims byte windows are cached against this slot's own "
            "bookkeeping counter, which is false: they are cached against the engine's own content "
            "generation counter instead",
        )

    def test_module_docstring_distinguishes_the_two_counters(self) -> None:
        """The corrected docstring must name both counters and say they are not the same number."""
        doc = registry.__doc__ or ""
        self.require(
            "HexDocument.generation()" in doc,
            "the module docstring does not name the engine's own content generation counter, so a "
            "reader has no way to learn it is a different counter from this slot's own",
        )
        self.require(
            "different number" in doc or "not the same number" in doc,
            "the module docstring does not say the slot's bookkeeping counter and the engine's content counter are distinct",
        )

    def test_document_info_generation_field_docstring_names_the_distinction(self) -> None:
        """``DocumentInfo.generation``'s own attribute doc must not repeat the false pairing claim."""
        doc = registry.DocumentInfo.__doc__ or ""
        self.require(
            "generation:" in doc,
            "DocumentInfo's docstring no longer documents the generation attribute at all",
        )
        self.require(
            "content generation counter" in doc or "engine's content" in doc,
            "DocumentInfo.generation's docstring does not point out that it is not the engine's "
            "own content generation counter that byte windows are paired with",
        )

    def test_bump_docstring_no_longer_implies_it_tracks_byte_content(self) -> None:
        """``DocumentSlot.bump``'s docstring must not suggest it tracks document bytes."""
        doc = registry.DocumentSlot.bump.__doc__ or ""
        self.require(
            "unrelated to the engine's content generation counter" in doc or "engine's content generation counter" in doc,
            "DocumentSlot.bump's docstring does not clarify that this counter is unrelated to the "
            "engine's own content generation counter that byte windows are paired with",
        )


if __name__ == "__main__":
    unittest.main()
