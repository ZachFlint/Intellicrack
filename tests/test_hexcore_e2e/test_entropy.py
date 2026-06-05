# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument entropy and statistical analysis methods.

Every test in this module drives a real ``HexDocument`` built from real
byte buffers through the native Rust entropy/statistics surface and pins
the result against an *independent* oracle computed from scratch in this
file (never copied from the implementation's own output). The oracles are
the textbook Shannon-entropy formula, the closed-form ``log2(k)`` value for
a uniform k-symbol block, and direct byte-category counting -- none of
which share code with ``intellicrack_hexcore``.
"""

from __future__ import annotations

import itertools
import math
from collections import Counter
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    import types

    from intellicrack_hexcore import HexDocument


def _shannon_entropy_bits_per_byte(data: bytes) -> float:
    """Compute Shannon entropy (bits per byte) via an independent oracle.

    This is a direct, from-scratch implementation of the textbook Shannon
    entropy formula ``H = -sum(p_i * log2(p_i))`` over the empirical byte
    distribution. It deliberately mirrors no Intellicrack production code so
    that it can serve as an independent expected-value oracle for the native
    ``HexDocument.entropy()`` method.

    Args:
        data: The byte buffer to measure.

    Returns:
        float: Shannon entropy in bits per byte, in the range [0.0, 8.0].
    """
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


class TestEntropy:
    """Tests for the entropy() method on HexDocument.

    Verifies that entropy values match an independent Shannon-entropy oracle
    for uniform-zero data, maximally varied data (all 256 byte values), a
    known two-symbol skewed distribution, and a balanced two-symbol stream.
    Every assertion pins an exact, independently-known value rather than a
    loose range so a wrong log base, an off-by-a-factor scaling bug, or a
    swap to a different statistic would all turn the test red.
    """

    def test_entropy_all_zeros_is_zero(self, hexcore: types.ModuleType) -> None:
        """Verify that entropy() returns 0.0 for a document with all identical bytes.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(bytes(256))
        result: float = doc.entropy()
        assert math.isclose(result, 0.0, abs_tol=1e-9)

    def test_entropy_uniform_256_matches_independent_oracle(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify entropy() equals the exact Shannon value for bytes(range(256)).

        A perfectly uniform distribution over all 256 byte values has an
        entropy of exactly 8.0 bits/byte. The expected value is computed by an
        independent oracle, not copied from the implementation, so an
        off-by-a-factor or wrong-log-base regression would be caught.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
            sample_bytes: The raw 256-byte payload (one of each byte value).
        """
        expected = _shannon_entropy_bits_per_byte(sample_bytes)
        assert math.isclose(expected, 8.0, abs_tol=1e-12)
        result = sample_doc_from_bytes.entropy()
        assert math.isclose(result, expected, abs_tol=1e-9)

    def test_entropy_skewed_two_symbol_matches_independent_oracle(self, hexcore: types.ModuleType) -> None:
        """Verify entropy() matches the exact value for a 75/25 two-symbol mix.

        A buffer of 192 ``0x00`` bytes and 64 ``0x01`` bytes has probabilities
        ``p0 = 0.75`` and ``p1 = 0.25``. The textbook entropy is
        ``-(0.75*log2(0.75) + 0.25*log2(0.25)) == 0.8112781244591328``. A loose
        ``> 7.9`` bound would never reach this region; only an exact match
        gates a correct calculation.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = b"\x00" * 192 + b"\x01" * 64
        expected = _shannon_entropy_bits_per_byte(data)
        assert math.isclose(expected, 0.8112781244591328, abs_tol=1e-12)
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.entropy()
        assert math.isclose(result, expected, abs_tol=1e-9)

    def test_entropy_balanced_two_symbol_is_exactly_one_bit(self, hexcore: types.ModuleType) -> None:
        """Verify entropy() is exactly 1.0 for an evenly split two-symbol stream.

        Two equiprobable symbols carry exactly one bit of entropy per byte.
        This pins the calculation at a clean, independently-known constant.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = b"\x00\x01" * 128
        expected = _shannon_entropy_bits_per_byte(data)
        assert math.isclose(expected, 1.0, abs_tol=1e-12)
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.entropy()
        assert math.isclose(result, expected, abs_tol=1e-9)

    def test_entropy_sixteen_symbol_block_is_exactly_four_bits(self, hexcore: types.ModuleType) -> None:
        """Verify entropy() is exactly 4.0 for a uniform 16-symbol stream.

        Sixteen equiprobable symbols (each appearing 16 times in a 256-byte
        buffer) carry exactly ``log2(16) == 4.0`` bits/byte. This is a third,
        non-trivial fixed point between the 1.0 and 8.0 anchors that would
        catch a scaling regression that a single end-point check could miss.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = bytes(value for value in range(16)) * 16
        expected = _shannon_entropy_bits_per_byte(data)
        assert math.isclose(expected, 4.0, abs_tol=1e-12)
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.entropy()
        assert math.isclose(result, expected, abs_tol=1e-9)

    def test_entropy_repeating_byte_is_zero(self, hexcore: types.ModuleType) -> None:
        """Verify that entropy() returns 0.0 for a single-distinct-byte document.

        A 512-byte run of ``0xAB`` is a one-symbol distribution, whose Shannon
        entropy is exactly 0.0 regardless of which byte value is repeated.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"\xab" * 512)
        result: float = doc.entropy()
        assert math.isclose(result, 0.0, abs_tol=1e-9)

    def test_entropy_single_byte_document_is_zero(self, hexcore: types.ModuleType) -> None:
        """Verify entropy() of a one-byte document is exactly 0.0.

        A length-1 buffer has a degenerate single-symbol distribution
        (``p == 1.0``), whose entropy is 0.0. This pins the smallest non-empty
        boundary input.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"\x42")
        result: float = doc.entropy()
        assert math.isclose(result, 0.0, abs_tol=1e-9)

    def test_entropy_empty_document_is_zero(self, hexcore: types.ModuleType) -> None:
        """Verify entropy() of an empty document is exactly 0.0.

        The zero-length boundary has no distribution; the independent oracle
        and the native implementation must agree on the conventional 0.0.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(b"")
        expected = _shannon_entropy_bits_per_byte(b"")
        assert math.isclose(expected, 0.0, abs_tol=1e-12)
        result: float = doc.entropy()
        assert math.isclose(result, expected, abs_tol=1e-9)


class TestEntropyMap:
    """Tests for the entropy_map() method on HexDocument.

    Verifies the block count is exactly ceil(length/block_size) and that each
    block's entropy equals the independent Shannon oracle computed over that
    exact slice of the buffer, not a loose [0, 8] range.
    """

    def test_entropy_map_block_count_matches_ceiling(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify the number of blocks equals ceil(doc_length / block_size).

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        block_size = 32
        doc_length = sample_doc_from_bytes.length()
        expected_blocks = math.ceil(doc_length / block_size)
        result = sample_doc_from_bytes.entropy_map(block_size)
        assert len(result) == expected_blocks

    def test_entropy_map_each_block_matches_independent_oracle(self, sample_bytes: bytes, sample_doc_from_bytes: HexDocument) -> None:
        """Verify every block value equals the Shannon oracle for its byte slice.

        For ``bytes(range(256))`` split into 32-byte blocks, each block holds
        32 distinct consecutive values, so its exact entropy is
        ``log2(32) == 5.0``. The oracle recomputes each block from the source
        bytes independently and the test asserts byte-slice-for-byte-slice
        equality, which would catch a block-misalignment or wrong-window bug
        that a range check could never detect.

        Args:
            sample_bytes: The raw 256-byte payload (one of each byte value).
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        block_size = 32
        result = sample_doc_from_bytes.entropy_map(block_size)
        expected = [
            _shannon_entropy_bits_per_byte(sample_bytes[start : start + block_size]) for start in range(0, len(sample_bytes), block_size)
        ]
        assert all(math.isclose(value, 5.0, abs_tol=1e-12) for value in expected)
        assert len(result) == len(expected)
        for actual_value, expected_value in zip(result, expected, strict=True):
            assert math.isclose(actual_value, expected_value, abs_tol=1e-9)

    def test_entropy_map_mixed_blocks_track_distinct_oracle_values(self, hexcore: types.ModuleType) -> None:
        """Verify a low-entropy block and a high-entropy block report distinct exact values.

        The first 16-byte block is all ``0x00`` (entropy 0.0); the second is
        ``range(16)`` (entropy ``log2(16) == 4.0``). The native map must report
        both exact values in order, proving each block is computed over its own
        window rather than the whole buffer.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = b"\x00" * 16 + bytes(range(16))
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.entropy_map(16)
        assert len(result) == 2
        assert math.isclose(result[0], 0.0, abs_tol=1e-9)
        assert math.isclose(result[1], 4.0, abs_tol=1e-9)

    def test_entropy_map_block_size_one_byte_all_zero(self, hexcore: types.ModuleType) -> None:
        """Verify block_size=1 yields one zero-entropy value per byte.

        With a one-byte window every block is a single symbol, so each entry
        is exactly 0.0 and the count equals the buffer length.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = bytes([0x00, 0xFF, 0xAA, 0x55])
        doc = hexcore.HexDocument.open_bytes(data)
        result = doc.entropy_map(1)
        assert len(result) == 4
        assert all(math.isclose(value, 0.0, abs_tol=1e-9) for value in result)


class TestByteDistribution:
    """Tests for the byte_distribution_full() method on HexDocument.

    Verifies the distribution is the exact 256-bucket histogram of the buffer,
    compared element-by-element against an independent Counter-based oracle.
    """

    def test_byte_distribution_full_matches_independent_histogram(self, sample_bytes: bytes, sample_doc_from_bytes: HexDocument) -> None:
        """Verify byte_distribution_full() equals an independent per-value histogram.

        The oracle builds the 256-length count vector with ``collections.Counter``
        and the test asserts full element-wise equality plus the 256-bucket
        shape, so any off-by-one binning or truncation would be caught.

        Args:
            sample_bytes: The raw 256-byte payload (one of each byte value).
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        counts = Counter(sample_bytes)
        expected = [counts.get(value, 0) for value in range(256)]
        result = sample_doc_from_bytes.byte_distribution_full()
        assert len(result) == 256
        assert list(result) == expected
        assert all(count == 1 for count in expected)

    def test_byte_distribution_skewed_buffer_matches_oracle(self, hexcore: types.ModuleType) -> None:
        """Verify a non-uniform buffer's histogram matches the Counter oracle exactly.

        A buffer of 100 ``0x41`` bytes, 30 ``0x42`` bytes, and 5 ``0xFF`` bytes
        must produce counts of exactly 100, 30, and 5 at those indices and zero
        elsewhere; the sum must equal the document length.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = b"\x41" * 100 + b"\x42" * 30 + b"\xff" * 5
        doc = hexcore.HexDocument.open_bytes(data)
        counts = Counter(data)
        expected = [counts.get(value, 0) for value in range(256)]
        result = doc.byte_distribution_full()
        assert list(result) == expected
        assert result[0x41] == 100
        assert result[0x42] == 30
        assert result[0xFF] == 5
        assert sum(result) == len(data) == doc.length()

    def test_byte_distribution_zeros_only(self, hexcore: types.ModuleType) -> None:
        """Verify that for all-zero data, only index 0 has a non-zero count.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(bytes(100))
        result = doc.byte_distribution_full()
        assert result[0] == 100
        assert all(count == 0 for count in result[1:])


class TestByteTypeDistribution:
    """Tests for the byte_type_distribution() method on HexDocument.

    Verifies the four category counts (null, printable, control, high) against
    an independent byte-category oracle, with the category boundaries fixed by
    the documented ASCII ranges rather than by re-using production code.
    """

    @staticmethod
    def _expected_categories(data: bytes) -> tuple[int, int, int, int]:
        """Count bytes per category using an independent classification oracle.

        Categories follow the documented contract: null is byte ``0x00``,
        printable is ``0x20``-``0x7E`` inclusive, high is ``>= 0x80``, and
        control is everything else (``0x01``-``0x1F`` and ``0x7F``).

        Args:
            data: The byte buffer to classify.

        Returns:
            tuple[int, int, int, int]: Counts of (null, printable, control, high).
        """
        null = sum(1 for b in data if b == 0)
        printable = sum(1 for b in data if 0x20 <= b <= 0x7E)
        high = sum(1 for b in data if b >= 0x80)
        control = len(data) - null - printable - high
        return (null, printable, control, high)

    def test_byte_type_distribution_full_range_matches_oracle(self, sample_bytes: bytes, sample_doc_from_bytes: HexDocument) -> None:
        """Verify byte_type_distribution() for bytes(range(256)) equals the oracle.

        Over all 256 values the independent oracle yields exactly
        ``(1, 95, 32, 128)``; the native tuple must match element-for-element
        and sum to the document length.

        Args:
            sample_bytes: The raw 256-byte payload (one of each byte value).
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        expected = self._expected_categories(sample_bytes)
        assert expected == (1, 95, 32, 128)
        result = sample_doc_from_bytes.byte_type_distribution()
        assert len(result) == 4
        assert tuple(result) == expected
        assert sum(result) == sample_doc_from_bytes.length()

    def test_byte_type_distribution_mixed_buffer_matches_oracle(self, hexcore: types.ModuleType) -> None:
        """Verify a hand-mixed buffer maps each byte to its correct category.

        The buffer mixes nulls, printable ASCII, control codes, and high bytes
        so every category is non-zero; the native counts must equal the
        independent oracle exactly.

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = b"\x00\x00\x00" + b"ABCDE" + b"\x01\x02\x1f\x7f" + b"\x80\x90\xff"
        doc = hexcore.HexDocument.open_bytes(data)
        expected = self._expected_categories(data)
        assert expected == (3, 5, 4, 3)
        result = doc.byte_type_distribution()
        assert tuple(result) == expected
        assert sum(result) == doc.length()


class TestDigramMatrix:
    """Tests for the digram_matrix() method on HexDocument.

    Verifies the matrix is the exact 256x256 transition histogram of adjacent
    byte pairs, compared against an independent pair-counting oracle.
    """

    def test_digram_matrix_matches_independent_pair_counts(self, hexcore: types.ModuleType) -> None:
        """Verify digram_matrix() equals an independent adjacent-pair histogram.

        For a known buffer the oracle counts each ``(prev, next)`` pair and
        places it at flat index ``prev*256 + next``. The test asserts the full
        65536-length matrix matches the oracle and that the total equals
        ``len(data) - 1`` (one digram per consecutive pair).

        Args:
            hexcore: The native hexcore module fixture.
        """
        data = bytes([0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF])
        doc = hexcore.HexDocument.open_bytes(data)
        expected = [0] * 65536
        for prev, nxt in itertools.pairwise(data):
            expected[prev * 256 + nxt] += 1
        result = doc.digram_matrix()
        assert len(result) == 65536
        assert list(result) == expected
        assert expected[0x00 * 256 + 0x01] == 2
        assert expected[0x01 * 256 + 0x00] == 1
        assert expected[0xFF * 256 + 0xFF] == 1
        assert sum(result) == len(data) - 1

    def test_digram_matrix_uniform_sum_equals_length_minus_one(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify the digram matrix total equals doc_length - 1 for the sample buffer.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.digram_matrix()
        assert sum(result) == sample_doc_from_bytes.length() - 1


class TestContentClassification:
    """Tests for the content_classification() method on HexDocument.

    Verifies the per-block class codes are valid integers in [0, 4], the block
    count is exactly ceil(length/block_size), and that distinct content kinds
    (all-zero low-entropy vs uniform high-entropy) receive distinct, expected
    class codes pinned by their independently-known entropy.
    """

    def test_content_classification_block_count_and_range(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify class codes count equals the ceiling and each is in [0, 4].

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        block_size = 64
        doc_length = sample_doc_from_bytes.length()
        expected_blocks = math.ceil(doc_length / block_size)
        result = sample_doc_from_bytes.content_classification(block_size)
        assert len(result) == expected_blocks
        assert all(0 <= int(code) <= 4 for code in result)

    def test_content_classification_low_vs_high_entropy_differ(self, hexcore: types.ModuleType) -> None:
        """Verify low-entropy and high-entropy blocks get distinct class codes.

        A 256-byte all-zero block has entropy 0.0 (the lowest class, code 0); a
        256-byte uniform block (``bytes(range(256))``) has the maximal entropy
        of 8.0 bits/byte, which the classifier reports as the high-entropy class
        (code 3). The two must differ, proving the classifier responds to real
        content rather than emitting a constant.

        Args:
            hexcore: The native hexcore module fixture.
        """
        low_doc = hexcore.HexDocument.open_bytes(bytes(256))
        high_doc = hexcore.HexDocument.open_bytes(bytes(range(256)))
        low_codes = low_doc.content_classification(256)
        high_codes = high_doc.content_classification(256)
        assert len(low_codes) == 1
        assert len(high_codes) == 1
        low_code = int(low_codes[0])
        high_code = int(high_codes[0])
        assert low_code == 0
        assert high_code == 3
        assert low_code != high_code


class TestEntropyErrorPaths:
    """Error-path and boundary coverage for the entropy/statistics surface.

    Confirms that a negative block size is surfaced as a typed exception
    rather than silently swallowed, that the zero block-size boundary yields
    an exact empty result, and that an out-of-range read is rejected with a
    diagnostic ``ValueError`` instead of returning garbage bytes.
    """

    def test_entropy_map_negative_block_size_raises_overflow(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify a negative block_size raises OverflowError, not a silent result.

        The native unsigned-size conversion must reject negative inputs so a
        caller bug surfaces immediately rather than producing meaningless data.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        with pytest.raises(OverflowError):
            sample_doc_from_bytes.entropy_map(-1)

    def test_content_classification_negative_block_size_raises_overflow(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify a negative block_size raises OverflowError in classification.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        with pytest.raises(OverflowError):
            sample_doc_from_bytes.content_classification(-32)

    def test_entropy_map_zero_block_size_returns_empty(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify a zero block_size yields an exactly empty block list.

        Zero is the degenerate windowing boundary; the implementation must
        return no blocks (an empty list) rather than hang or divide by zero.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.entropy_map(0)
        assert list(result) == []

    def test_read_beyond_document_size_raises_value_error(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify reading past the end raises a diagnostic ValueError.

        The error message must name the offending offset and the document
        size so the failure is actionable rather than swallowed.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        with pytest.raises(ValueError, match="beyond document size"):
            sample_doc_from_bytes.read(300, 16)
