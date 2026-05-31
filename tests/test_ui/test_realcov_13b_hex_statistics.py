# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for ``hex_editor.statistics.compute_statistics``.

The audit (shard 13) flagged ``statistics.py`` as having no dedicated test
coverage: entropy correctness, byte-distribution accuracy, and byte-type
classification were entirely unexercised. These tests run the real
:func:`compute_statistics` pure function over genuine compiled binaries
(a real Windows PE plus the committed ELF and Mach-O corpus fixtures), each
loaded into the real ``intellicrack_hexcore.HexDocument`` backend, and assert
the computed entropy/distribution/type counts against independent reference
calculations derived directly from the same file bytes.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.panels.hex_editor.statistics import compute_statistics


if TYPE_CHECKING:
    from pathlib import Path


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real document statistics",
)


pytestmark = pytest.mark.integration


_ENTROPY_BLOCK_SIZE: int = 4096
_PRINTABLE_MIN: int = 0x20
_PRINTABLE_MAX: int = 0x7E


def _open_document(path: Path) -> object:
    """Open a real binary file as a hexcore document.

    Args:
        path: Path to a real compiled binary on disk.

    Returns:
        object: A loaded ``intellicrack_hexcore.HexDocument`` instance.
    """
    return hexcore.HexDocument.open(str(path))


def _reference_entropy(data: bytes) -> float:
    """Compute Shannon entropy of ``data`` independently of production code.

    Args:
        data: Raw file bytes.

    Returns:
        float: Entropy in bits per byte.
    """
    total = len(data)
    if total == 0:
        return 0.0
    counts = Counter(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class TestEntropyMatchesReference:
    """Computed entropy must match an independent reference over real bytes."""

    def test_pe_entropy_matches_file_bytes(self, real_pe_dll: Path) -> None:
        """Verify entropy over a real PE equals the reference within tolerance.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        doc = _open_document(real_pe_dll)
        result = compute_statistics(doc, _ENTROPY_BLOCK_SIZE)
        expected = _reference_entropy(real_pe_dll.read_bytes())
        assert result.total == real_pe_dll.stat().st_size
        assert result.entropy == pytest.approx(expected, abs=1e-9)
        assert 0.0 <= result.entropy <= 8.0

    def test_elf_entropy_matches_file_bytes(self, real_elf_binary: Path) -> None:
        """Verify entropy over the real ELF corpus fixture matches the reference.

        Args:
            real_elf_binary: Real ELF fixture path.
        """
        doc = _open_document(real_elf_binary)
        result = compute_statistics(doc, _ENTROPY_BLOCK_SIZE)
        expected = _reference_entropy(real_elf_binary.read_bytes())
        assert result.entropy == pytest.approx(expected, abs=1e-9)

    def test_macho_entropy_matches_file_bytes(self, real_macho_binary: Path) -> None:
        """Verify entropy over the real Mach-O corpus fixture matches the reference.

        Args:
            real_macho_binary: Real Mach-O fixture path.
        """
        doc = _open_document(real_macho_binary)
        result = compute_statistics(doc, _ENTROPY_BLOCK_SIZE)
        expected = _reference_entropy(real_macho_binary.read_bytes())
        assert result.entropy == pytest.approx(expected, abs=1e-9)


class TestByteDistributionMatchesReference:
    """The 256-bin byte distribution must match a Counter over real bytes."""

    def test_distribution_counts_match_real_pe(self, real_pe_dll: Path) -> None:
        """Verify byte-frequency counts equal a reference histogram of the PE.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        data = real_pe_dll.read_bytes()
        doc = _open_document(real_pe_dll)
        result = compute_statistics(doc, _ENTROPY_BLOCK_SIZE)
        assert result.dist_counts is not None
        assert len(result.dist_counts) == 256
        ref = Counter(data)
        for value in range(256):
            assert result.dist_counts[value] == ref.get(value, 0)
        assert sum(result.dist_counts) == len(data)

    def test_byte_stats_match_distribution(self, real_pe_dll: Path) -> None:
        """Verify the byte_statistics tuples reconcile with the full distribution.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        doc = _open_document(real_pe_dll)
        result = compute_statistics(doc, _ENTROPY_BLOCK_SIZE)
        assert result.dist_counts is not None
        for byte_val, count in result.byte_stats:
            assert result.dist_counts[byte_val] == count


class TestByteTypeDistribution:
    """Byte-type classification counts must match a reference partition."""

    def test_type_distribution_partitions_real_pe(self, real_pe_dll: Path) -> None:
        """Verify null/printable/control/high counts sum to the file size.

        The exact null and printable counts are cross-checked against an
        independent partition of the real PE bytes.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        data = real_pe_dll.read_bytes()
        doc = _open_document(real_pe_dll)
        result = compute_statistics(doc, _ENTROPY_BLOCK_SIZE)
        assert result.type_dist is not None
        assert len(result.type_dist) >= 4
        null_c, printable_c, _control_c, high_c = result.type_dist[:4]
        assert sum(result.type_dist) == len(data)
        assert null_c == data.count(0)
        ref_printable = sum(1 for b in data if _PRINTABLE_MIN <= b <= _PRINTABLE_MAX)
        assert printable_c == ref_printable
        assert high_c == sum(1 for b in data if b >= 0x80)


class TestPerBlockAnalysis:
    """Per-block entropy and classification must align with file size."""

    def test_entropy_map_block_count(self, real_pe_dll: Path) -> None:
        """Verify per-block entropy has one entry per 4 KiB block of the PE.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        size = real_pe_dll.stat().st_size
        doc = _open_document(real_pe_dll)
        result = compute_statistics(doc, _ENTROPY_BLOCK_SIZE)
        assert result.entropy_values is not None
        expected_blocks = math.ceil(size / _ENTROPY_BLOCK_SIZE)
        assert len(result.entropy_values) == expected_blocks
        assert all(0.0 <= v <= 8.0 for v in result.entropy_values)

    def test_classification_block_count(self, real_pe_dll: Path) -> None:
        """Verify per-block content classification spans the whole PE.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        size = real_pe_dll.stat().st_size
        doc = _open_document(real_pe_dll)
        result = compute_statistics(doc, _ENTROPY_BLOCK_SIZE)
        assert result.classification is not None
        expected_blocks = math.ceil(size / _ENTROPY_BLOCK_SIZE)
        assert len(result.classification) == expected_blocks
        assert all(0 <= c <= 4 for c in result.classification)
