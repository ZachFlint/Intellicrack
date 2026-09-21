# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for ``HashingMixin._apply_pe_checksum_verification``.

Covers the 2026-09-20 Qodana ``PyStringFormatInspection`` (``Any | None``)
finding: ``stored``/``calculated`` were narrowed with a single compound
``if not isinstance(stored, int) or not isinstance(calculated, int): return``
guard. That guard is sound -- past it, both values are provably ``int`` --
but two-variable compound-``or`` narrowing is a known blind spot for some
flow-analysis engines, so it is split into two sequential single-variable
``isinstance`` guards. Both forms are behaviourally identical; this test
locks in the real, falsifiable property the guard exists to protect: a
non-int ``stored``/``calculated`` in the worker's result dict must render
"Verification unavailable" rather than reaching the ``:08X`` format spec
(which would raise ``TypeError`` for a non-numeric value).
"""

from __future__ import annotations

from typing import Any

import pytest
from PyQt6.QtWidgets import QLabel, QWidget

from intellicrack.ui.panels.hex_editor.hashing import HashingMixin


pytestmark = pytest.mark.usefixtures("qapp")


class _PeChecksumHarness(QWidget, HashingMixin):
    """Minimal ``HashingMixin`` consumer exercising only the checksum-verify path."""

    def __init__(self) -> None:
        """Wire only the ``_pe_checksum_status`` slot the mixin method reads."""
        QWidget.__init__(self)
        self._pe_checksum_status = QLabel("Not verified")

    def apply_pe_checksum_verification(self, info: object) -> None:
        """Invoke the mixin verification-apply flow as a public test entry point.

        Args:
            info: The raw result returned by ``document.verify_pe_checksum``.
        """
        self._apply_pe_checksum_verification(info)


def test_matching_int_stored_and_calculated_renders_valid() -> None:
    """Equal int ``stored``/``calculated`` render the ``Valid`` message in hex."""
    harness = _PeChecksumHarness()

    harness.apply_pe_checksum_verification({"stored": 0xABCD1234, "calculated": 0xABCD1234})

    assert harness._pe_checksum_status is not None
    assert harness._pe_checksum_status.text() == "Valid: 0xABCD1234"


def test_mismatched_int_stored_and_calculated_renders_invalid_with_both_values() -> None:
    """Unequal int ``stored``/``calculated`` render both values in the ``Invalid`` message."""
    harness = _PeChecksumHarness()

    harness.apply_pe_checksum_verification({"stored": 0x00000001, "calculated": 0x00000002})

    assert harness._pe_checksum_status is not None
    assert harness._pe_checksum_status.text() == "Invalid: stored=0x00000001, expected=0x00000002"


@pytest.mark.parametrize(
    "info",
    [
        pytest.param({"stored": "not-a-number", "calculated": 1}, id="stored-is-str"),
        pytest.param({"stored": 1, "calculated": "not-a-number"}, id="calculated-is-str"),
        pytest.param({"stored": None, "calculated": 1}, id="stored-is-none"),
        pytest.param({"stored": 1, "calculated": None}, id="calculated-is-none"),
        pytest.param({"stored": 1.5, "calculated": 1.5}, id="both-are-float"),
    ],
)
def test_non_int_stored_or_calculated_renders_unavailable_without_crashing(info: dict[str, Any]) -> None:
    """A non-int ``stored`` or ``calculated`` must not reach the ``:08X`` format spec.

    Regression target: reverting the split guard back to a single
    ``isinstance(stored, int) or isinstance(calculated, int)``-style
    condition that a weaker flow engine cannot narrow would let a
    non-int value reach ``f"...:08X}"`` and raise ``TypeError`` instead
    of rendering the safe fallback message.

    Args:
        info: A malformed verification result missing a genuine int on
            one or both sides.
    """
    harness = _PeChecksumHarness()

    harness.apply_pe_checksum_verification(info)

    assert harness._pe_checksum_status is not None
    assert harness._pe_checksum_status.text() == "Verification unavailable"


def test_non_dict_result_renders_unavailable() -> None:
    """A non-dict result (worker failure payload shape) renders the safe fallback."""
    harness = _PeChecksumHarness()

    harness.apply_pe_checksum_verification("not-a-dict")

    assert harness._pe_checksum_status is not None
    assert harness._pe_checksum_status.text() == "Verification unavailable"
