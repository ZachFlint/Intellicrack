# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument entropy and statistical analysis methods."""

from __future__ import annotations

import math
from typing import Any


class TestEntropy:
    """Tests for the entropy() method on HexDocument.

    Verifies that entropy calculations are correct for uniform zero data,
    maximally varied data (all 256 byte values), and constrained to the
    valid range [0.0, 8.0].
    """

    def test_entropy_all_zeros_is_zero(self, hexcore: Any) -> None:
        """Verify that entropy() returns 0.0 for a document with all identical bytes.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(bytes(256))
        result: float = doc.entropy()
        assert abs(result) < 1e-6

    def test_entropy_sample_bytes_near_max(self, sample_doc_from_bytes: Any) -> None:
        """Verify that entropy() exceeds 7.9 for a uniform byte distribution.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.entropy()
        assert result > 7.9

    def test_entropy_sample_bytes_at_most_eight(self, sample_doc_from_bytes: Any) -> None:
        """Verify that entropy() never exceeds 8.0 for any document.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.entropy()
        assert result <= 8.0

    def test_entropy_is_float(self, sample_doc_from_bytes: Any) -> None:
        """Verify that entropy() returns a float value.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.entropy()
        assert isinstance(result, float)

    def test_entropy_lower_bound(self, sample_doc_from_bytes: Any) -> None:
        """Verify that entropy() is non-negative for any document.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.entropy()
        assert result >= 0.0

    def test_entropy_repeating_byte_is_zero(self, hexcore: Any) -> None:
        """Verify that entropy() returns 0.0 for a document with one distinct byte value.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"\xAB" * 512)
        result: float = doc.entropy()
        assert abs(result) < 1e-6


class TestEntropyMap:
    """Tests for the entropy_map() method on HexDocument.

    Verifies that the entropy map returns one block per ceil(length/block_size),
    all block values are in [0.0, 8.0], and smaller block sizes yield more blocks.
    """

    def test_entropy_map_returns_list_of_floats(self, sample_doc_from_bytes: Any) -> None:
        """Verify that entropy_map() returns a list of float values.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result: list[float] = sample_doc_from_bytes.entropy_map(32)
        assert isinstance(result, list)
        assert all(isinstance(v, (int, float)) for v in result)

    def test_entropy_map_block_values_in_range(self, sample_doc_from_bytes: Any) -> None:
        """Verify that every block entropy value is between 0.0 and 8.0 inclusive.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result: list[float] = sample_doc_from_bytes.entropy_map(32)
        for v in result:
            assert 0.0 <= v <= 8.0

    def test_entropy_map_block_count_matches_doc_length(self, sample_doc_from_bytes: Any) -> None:
        """Verify that the number of blocks equals ceil(doc_length / block_size).

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        block_size = 32
        doc_length = sample_doc_from_bytes.length()
        expected_blocks = math.ceil(doc_length / block_size)
        result = sample_doc_from_bytes.entropy_map(block_size)
        assert len(result) == expected_blocks

    def test_entropy_map_smaller_block_size_gives_more_blocks(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that a smaller block_size produces more entropy map blocks.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        large_block = sample_doc_from_bytes.entropy_map(64)
        small_block = sample_doc_from_bytes.entropy_map(16)
        assert len(small_block) > len(large_block)

    def test_entropy_map_block_size_one_byte(self, hexcore: Any) -> None:
        """Verify that entropy_map() with block_size=1 returns one value per byte.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = bytes([0x00, 0xFF, 0xAA, 0x55])
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.entropy_map(1)
        assert len(result) == 4


class TestByteDistribution:
    """Tests for the byte_distribution_full() method on HexDocument.

    Verifies that the distribution has exactly 256 buckets, that the sum
    equals the document length, and that a uniform distribution has count 1
    for every byte value.
    """

    def test_byte_distribution_full_has_256_elements(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that byte_distribution_full() returns exactly 256 integer counts.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.byte_distribution_full()
        assert len(result) == 256

    def test_byte_distribution_sum_equals_document_length(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that the sum of all distribution counts equals the document length.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.byte_distribution_full()
        doc_length = sample_doc_from_bytes.length()
        assert sum(result) == doc_length

    def test_byte_distribution_uniform_all_ones(self, sample_doc_from_bytes: Any) -> None:
        """Verify that for bytes(range(256)), every byte value has a count of exactly 1.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.byte_distribution_full()
        assert all(count == 1 for count in result)

    def test_byte_distribution_zeros_only(self, hexcore: Any) -> None:
        """Verify that for all-zero data, only index 0 has a non-zero count.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(bytes(100))
        result = doc.byte_distribution_full()
        assert result[0] == 100
        assert all(count == 0 for count in result[1:])

    def test_byte_distribution_returns_ints(self, sample_doc_from_bytes: Any) -> None:
        """Verify that byte_distribution_full() returns a list of int values.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.byte_distribution_full()
        assert all(isinstance(count, int) for count in result)


class TestByteTypeDistribution:
    """Tests for the byte_type_distribution() method on HexDocument.

    Verifies return shape, total count invariant, and known counts for
    specific controlled data (null/printable/control/high-byte categories).
    """

    def test_byte_type_distribution_returns_four_values(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that byte_type_distribution() returns a tuple of exactly 4 elements.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.byte_type_distribution()
        assert len(result) == 4

    def test_byte_type_distribution_sum_equals_document_length(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that the sum of all byte type counts equals the document length.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.byte_type_distribution()
        doc_length = sample_doc_from_bytes.length()
        assert sum(result) == doc_length

    def test_byte_type_distribution_null_count(self, hexcore: Any) -> None:
        """Verify that a single-null-byte document has a null count of 1.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"\x00")
        result = doc.byte_type_distribution()
        null_count = result[0]
        assert null_count == 1

    def test_byte_type_distribution_printable_count(self, hexcore: Any) -> None:
        """Verify that a document of ASCII printable text has printable count equal to its length.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = b"ABCDEFGHIJ"
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.byte_type_distribution()
        printable_count = result[1]
        assert printable_count == len(data)

    def test_byte_type_distribution_high_bytes_count(self, hexcore: Any) -> None:
        """Verify that a document of high bytes (0x80-0xFF) has high-byte count equal to its length.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = bytes(range(0x80, 0x100))
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.byte_type_distribution()
        high_count = result[3]
        assert high_count == len(data)


class TestDigramMatrix:
    """Tests for the digram_matrix() method on HexDocument.

    Verifies the matrix has 65536 elements and that the sum of all cells
    equals doc_length - 1 (one digram per consecutive byte pair).
    """

    def test_digram_matrix_has_65536_elements(self, sample_doc_from_bytes: Any) -> None:
        """Verify that digram_matrix() returns a flat list of 65536 integers.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.digram_matrix()
        assert len(result) == 65536

    def test_digram_matrix_sum_equals_length_minus_one(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that the sum of the digram matrix equals doc_length - 1.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.digram_matrix()
        doc_length = sample_doc_from_bytes.length()
        assert sum(result) == doc_length - 1

    def test_digram_matrix_single_known_pair(self, hexcore: Any) -> None:
        """Verify that two-byte data [0x00, 0x01] sets digram[0x00][0x01] to 1.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(bytes([0x00, 0x01]))
        matrix = doc.digram_matrix()
        index = 0x00 * 256 + 0x01
        assert matrix[index] == 1


class TestContentClassification:
    """Tests for the content_classification() method on HexDocument.

    Verifies that the method returns a list of integers with each value in
    the range [0, 4] and that the count of blocks matches the expected ceiling.
    """

    def test_content_classification_returns_list(self, sample_doc_from_bytes: Any) -> None:
        """Verify that content_classification() returns a list.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.content_classification(64)
        assert isinstance(result, list)

    def test_content_classification_values_in_range(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that every classification value is an integer in the range [0, 4].

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.content_classification(32)
        for value in result:
            assert isinstance(value, int)
            assert 0 <= value <= 4

    def test_content_classification_block_count(self, sample_doc_from_bytes: Any) -> None:
        """Verify that the number of blocks equals ceil(doc_length / block_size).

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        block_size = 64
        doc_length = sample_doc_from_bytes.length()
        expected_blocks = math.ceil(doc_length / block_size)
        result = sample_doc_from_bytes.content_classification(block_size)
        assert len(result) == expected_blocks

    def test_content_classification_zeros_classified_low_entropy(
        self, hexcore: Any
    ) -> None:
        """Verify that all-zero data receives a low-entropy classification (0 or 1).

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(bytes(256))
        result = doc.content_classification(256)
        assert len(result) >= 1
        assert result[0] in {0, 1}
