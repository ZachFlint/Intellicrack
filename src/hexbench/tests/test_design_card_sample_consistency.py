# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The design cards must never show decoded readings that disagree with their own sample bytes.

``design/build_cards.py`` renders three tables whose whole documented point is
that they describe the real 640 byte sample header rather than invented
numbers: the inspector panel's per-format readings, the status bar's entropy
figure, and the argument-row gallery's kind count. Each of those tables used
to carry literals that were never actually derived from the sample bytes
alongside it, so nothing caught them drifting away from what the sample
actually contains.

These tests run the real generator, read the HTML it actually wrote, and
independently recompute the same figures from the same sample bytes -- using
fresh implementations of the decoding, not the generator's own private
helpers -- so a reintroduced mismatch between a card and its sample is caught
in the one place a reader would actually see it.
"""

from __future__ import annotations

import re
import unittest
import uuid
from collections import Counter
from datetime import UTC, datetime
from math import log2
from pathlib import Path
from struct import unpack_from
from typing import Final

from hexbench.design import build_cards as cards_module
from hexbench.tests._support import Assertions


_KV_ROW: Final = re.compile(r'<td class="hb-kv-key">([^<]*)</td><td class="hb-kv-value[^"]*">([^<]*)</td>')
_STATUS_ENTROPY_VALUE: Final = re.compile(r'<span class="hb-status-key">entropy</span><span class="hb-status-value">([^<]*)</span>')
_FRAME_LABEL: Final = re.compile(r'<div class="ds-frame-label">(All \d+ kinds)</div>')
_KIND_BADGE: Final = re.compile(r'<span class="hb-badge is-mono">')

_UTC_STAMP: Final = "%Y-%m-%dT%H:%M:%SZ"


def _cards_directory() -> Path:
    """Locate the directory :func:`build_cards.build_cards` writes into.

    Returns:
        Path: The ``cards`` directory beside the generator module.
    """
    return Path(cards_module.__file__).resolve().parent / "cards"


def _read_card(filename: str) -> str:
    """Read one already-generated card file.

    Args:
        filename: Name of the card file to read.

    Returns:
        str: The card's complete HTML text.
    """
    return (_cards_directory() / filename).read_text(encoding="utf-8")


def _shannon_entropy(data: bytes) -> float:
    """Compute the Shannon entropy of a byte run, independently of the generator's own helper.

    Args:
        data: Bytes to measure.

    Returns:
        float: Entropy in bits per byte, or 0.0 for an empty run.
    """
    if not data:
        return 0.0
    total = len(data)
    return -sum((count / total) * log2(count / total) for count in Counter(data).values())


class InspectorRowsMatchTheSampleBytesTests(Assertions, unittest.TestCase):
    """Every inspector reading must be the real decode of the leading sample bytes."""

    @classmethod
    def setUpClass(cls) -> None:
        """Generate every design card once, before any test in this class reads one."""
        cards_module.build_cards()

    def setUp(self) -> None:
        """Read the generated inspector card and index its rows by key."""
        html = _read_card("panels-inspector.html")
        self.rows = dict(_KV_ROW.findall(html))
        self.window = cards_module.sample_bytes()[:16]

    def test_int16_le_matches_a_direct_struct_decode(self) -> None:
        """``int16_le`` must equal a plain little-endian decode of the first two bytes."""
        expected = unpack_from("<h", self.window)[0]
        self.equal(self.rows["int16_le"], str(expected), "int16_le")

    def test_rgb565_matches_bit_packing_of_the_same_two_bytes(self) -> None:
        """``rgb565`` must decode the same little-endian 16-bit window used by ``int16_le``."""
        raw: int = unpack_from("<H", self.window)[0]
        red5, green6, blue5 = (raw >> 11) & 0x1F, (raw >> 5) & 0x3F, raw & 0x1F
        expected = f"#{round(red5 * 255 / 0x1F):02x}{round(green6 * 255 / 0x3F):02x}{round(blue5 * 255 / 0x1F):02x}"
        self.equal(self.rows["rgb565"], expected, "rgb565")

    def test_dos_date_matches_ms_dos_bit_packing(self) -> None:
        """``dos_date`` must decode the MS-DOS date bitfields of the same 16-bit window."""
        raw: int = unpack_from("<H", self.window)[0]
        expected = f"{1980 + ((raw >> 9) & 0x7F)}-{(raw >> 5) & 0x0F:02d}-{raw & 0x1F:02d}"
        self.equal(self.rows["dos_date"], expected, "dos_date")

    def test_dos_time_matches_ms_dos_bit_packing(self) -> None:
        """``dos_time`` must decode the MS-DOS time bitfields of the same 16-bit window."""
        raw: int = unpack_from("<H", self.window)[0]
        expected = f"{(raw >> 11) & 0x1F:02d}:{(raw >> 5) & 0x3F:02d}:{(raw & 0x1F) * 2:02d}"
        self.equal(self.rows["dos_time"], expected, "dos_time")

    def test_float32_matches_a_direct_struct_decode(self) -> None:
        """``float32`` must equal a plain little-endian ``float`` decode of the first four bytes."""
        expected: float = unpack_from("<f", self.window)[0]
        self.equal(self.rows["float32"], f"{expected:.4e}", "float32")

    def test_float64_matches_a_direct_struct_decode(self) -> None:
        """``float64`` must equal a plain little-endian ``double`` decode of all sixteen bytes."""
        expected: float = unpack_from("<d", self.window)[0]
        self.equal(self.rows["float64"], f"{expected:.4e}", "float64")

    def test_unix_timestamp_matches_a_direct_struct_decode(self) -> None:
        """``unix_timestamp`` must equal the UTC rendering of a little-endian ``u32`` decode."""
        seconds: int = unpack_from("<I", self.window)[0]
        expected = datetime.fromtimestamp(seconds, tz=UTC).strftime(_UTC_STAMP)
        self.equal(self.rows["unix_timestamp"], expected, "unix_timestamp")

    def test_guid_matches_a_direct_uuid_decode(self) -> None:
        """``guid`` must equal the little-endian ``UUID`` decode of all sixteen bytes."""
        expected = str(uuid.UUID(bytes_le=self.window))
        self.equal(self.rows["guid"], expected, "guid")

    def test_every_declared_row_key_is_present(self) -> None:
        """None of the fifteen documented readings were dropped while the table was recomputed."""
        expected_keys = {
            "int8",
            "uint8",
            "int16_le",
            "int16_be",
            "rgb565",
            "dos_date",
            "dos_time",
            "float32",
            "rgba8",
            "ipv4",
            "unix_timestamp",
            "float64",
            "filetime",
            "guid",
            "wide_string",
        }
        self.equal(set(self.rows), expected_keys, "the set of inspector row keys")


class StatusBarEntropyMatchesTheSampleTests(Assertions, unittest.TestCase):
    """The status bar's entropy reading must be the sample's real Shannon entropy."""

    @classmethod
    def setUpClass(cls) -> None:
        """Generate every design card once, before any test in this class reads one."""
        cards_module.build_cards()

    def test_entropy_reading_matches_entropy_of_the_whole_sample(self) -> None:
        """The declared entropy figure must equal the sample's Shannon entropy to two decimal places."""
        html = _read_card("chrome-statusbar.html")
        match = _STATUS_ENTROPY_VALUE.search(html)
        if match is None:
            self.fail("no entropy reading found in the status bar card")
        expected = f"{_shannon_entropy(cards_module.sample_bytes()):.2f}"
        self.equal(match.group(1), expected, "status bar entropy")

    def test_entropy_reading_is_not_the_selection_slice_by_coincidence(self) -> None:
        """The whole-document and selection entropy figures must genuinely differ for this sample.

        Without this control, a status bar value that happened to match both
        candidates would not tell us which one the generator actually used.
        """
        sample = cards_module.sample_bytes()
        whole = _shannon_entropy(sample)
        selection = _shannon_entropy(sample[0x40:0x4E])
        self.unequal(round(whole, 2), round(selection, 2), "whole-document vs. selection entropy")


class ArgumentRowCaptionMatchesTheRenderedKindCountTests(Assertions, unittest.TestCase):
    """The argument-row gallery caption must count the kinds it actually renders."""

    @classmethod
    def setUpClass(cls) -> None:
        """Generate every design card once, before any test in this class reads one."""
        cards_module.build_cards()

    def test_caption_names_exactly_the_number_of_rendered_kind_badges(self) -> None:
        """The caption's stated count must equal the number of kind badges the same page renders."""
        html = _read_card("operations-arguments.html")
        label_match = _FRAME_LABEL.search(html)
        if label_match is None:
            self.fail("no 'All N kinds' caption found in the argument-rows card")
        badge_count = len(_KIND_BADGE.findall(html))
        self.equal(label_match.group(1), f"All {badge_count} kinds", "the argument-row gallery caption")

    def test_rendered_kind_count_is_not_nine(self) -> None:
        """A control against the exact defect reported: the true rendered count is not nine."""
        html = _read_card("operations-arguments.html")
        badge_count = len(_KIND_BADGE.findall(html))
        self.unequal(badge_count, 9, "count of rendered kind badges")


if __name__ == "__main__":
    unittest.main()
