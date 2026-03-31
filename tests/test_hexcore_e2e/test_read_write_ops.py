# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument read, write, insert, and delete operations."""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from intellicrack_hexcore import HexDocument


class TestReadOps:
    """Tests covering read() and read_byte() against known data."""

    def test_read_returns_correct_bytes_at_offset(self, sample_doc: HexDocument, sample_bytes: bytes) -> None:
        """Verify that read() at a non-zero offset returns the expected slice.

        Args:
            sample_doc: HexDocument loaded from disk fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        result = sample_doc.read(16, 8)
        assert result == sample_bytes[16:24]

    def test_read_byte_returns_correct_single_byte(self, sample_doc: HexDocument, sample_bytes: bytes) -> None:
        """Verify that read_byte() returns the integer value at a specific offset.

        Args:
            sample_doc: HexDocument loaded from disk fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        for offset in (0, 1, 127, 128, 255):
            assert sample_doc.read_byte(offset) == sample_bytes[offset]

    def test_read_at_offset_zero_full_length(self, sample_doc: HexDocument, sample_bytes: bytes) -> None:
        """Verify that reading from offset 0 with full length returns all bytes.

        Args:
            sample_doc: HexDocument loaded from disk fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        result = sample_doc.read(0, len(sample_bytes))
        assert result == sample_bytes

    def test_read_partial_range(self, sample_doc: HexDocument, sample_bytes: bytes) -> None:
        """Verify that read() returns exactly the requested sub-range.

        Args:
            sample_doc: HexDocument loaded from disk fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        result = sample_doc.read(100, 50)
        assert result == sample_bytes[100:150]
        assert len(result) == 50

    def test_read_across_byte_boundaries(self, sample_doc: HexDocument) -> None:
        """Verify reads that span the 0x7F/0x80 and 0xFE/0xFF boundaries.

        Args:
            sample_doc: HexDocument loaded from disk fixture.
        """
        boundary_low = sample_doc.read(126, 4)
        assert boundary_low == bytes([0x7E, 0x7F, 0x80, 0x81])

        boundary_high = sample_doc.read(253, 3)
        assert boundary_high == bytes([0xFD, 0xFE, 0xFF])

    def test_read_single_byte_via_read(self, sample_doc: HexDocument, sample_bytes: bytes) -> None:
        """Verify that read() with length 1 returns a single-byte bytes object.

        Args:
            sample_doc: HexDocument loaded from disk fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        for offset in (0, 64, 128, 255):
            result = sample_doc.read(offset, 1)
            assert result == bytes([sample_bytes[offset]])


class TestWriteOps:
    """Tests covering write_bytes() correctness and side-effects."""

    def test_write_bytes_overwrites_correctly(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that write_bytes() replaces bytes at the target offset.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        payload = b"\xde\xad\xbe\xef"
        sample_doc_from_bytes.write_bytes(10, payload)
        assert sample_doc_from_bytes.read(10, 4) == payload

    def test_write_then_read_back_verifies_data(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that a written payload reads back identically.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        payload = bytes(range(16))
        sample_doc_from_bytes.write_bytes(0, payload)
        result = sample_doc_from_bytes.read(0, 16)
        assert result == payload

    def test_write_does_not_change_surrounding_bytes(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that write_bytes() only modifies the targeted range.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
            sample_bytes: The 256-byte payload fixture.
        """
        sample_doc_from_bytes.write_bytes(50, b"\xaa\xbb")
        assert sample_doc_from_bytes.read(48, 2) == sample_bytes[48:50]
        assert sample_doc_from_bytes.read(52, 2) == sample_bytes[52:54]

    def test_write_at_end_of_document(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that write_bytes() works when targeting the last bytes.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
            sample_bytes: The 256-byte payload fixture.
        """
        last_offset = len(sample_bytes) - 4
        sample_doc_from_bytes.write_bytes(last_offset, b"\x01\x02\x03\x04")
        assert sample_doc_from_bytes.read(last_offset, 4) == b"\x01\x02\x03\x04"

    def test_write_marks_document_as_modified(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that writing to a document sets is_modified() to True.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\xff")
        assert sample_doc_from_bytes.is_modified()


class TestInsertOps:
    """Tests covering insert_bytes() length changes and data shifting."""

    def test_insert_increases_length(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that insert_bytes() increases the document length by the inserted size.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
            sample_bytes: The 256-byte payload fixture.
        """
        extra = b"\xaa\xbb\xcc"
        sample_doc_from_bytes.insert_bytes(0, extra)
        assert sample_doc_from_bytes.length() == len(sample_bytes) + len(extra)

    def test_insert_at_beginning_shifts_data(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that inserting at offset 0 shifts existing bytes forward.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
            sample_bytes: The 256-byte payload fixture.
        """
        prefix = b"\x11\x22\x33"
        sample_doc_from_bytes.insert_bytes(0, prefix)
        assert sample_doc_from_bytes.read(0, 3) == prefix
        assert sample_doc_from_bytes.read(3, 3) == sample_bytes[:3]

    def test_insert_in_middle_preserves_surrounding_data(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that a mid-document insert preserves both halves of existing data.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
            sample_bytes: The 256-byte payload fixture.
        """
        insert_at = 10
        insertion = b"\xca\xfe"
        sample_doc_from_bytes.insert_bytes(insert_at, insertion)
        assert sample_doc_from_bytes.read(0, insert_at) == sample_bytes[:insert_at]
        assert sample_doc_from_bytes.read(insert_at, 2) == insertion
        assert sample_doc_from_bytes.read(insert_at + 2, 5) == sample_bytes[insert_at : insert_at + 5]


class TestDeleteOps:
    """Tests covering delete_bytes() length changes and data compaction."""

    def test_delete_decreases_length(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that delete_bytes() reduces the document length by the deleted count.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
            sample_bytes: The 256-byte payload fixture.
        """
        sample_doc_from_bytes.delete_bytes(0, 10)
        assert sample_doc_from_bytes.length() == len(sample_bytes) - 10

    def test_delete_from_beginning_exposes_next_bytes(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that deleting from offset 0 shifts subsequent bytes to the front.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
            sample_bytes: The 256-byte payload fixture.
        """
        n = 5
        sample_doc_from_bytes.delete_bytes(0, n)
        assert sample_doc_from_bytes.read(0, n) == sample_bytes[n : n * 2]

    def test_delete_from_middle_preserves_surrounding_data(self, sample_doc_from_bytes: HexDocument, sample_bytes: bytes) -> None:
        """Verify that a mid-document delete closes the gap cleanly.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
            sample_bytes: The 256-byte payload fixture.
        """
        delete_at = 20
        delete_len = 8
        sample_doc_from_bytes.delete_bytes(delete_at, delete_len)
        assert sample_doc_from_bytes.read(0, delete_at) == sample_bytes[:delete_at]
        assert sample_doc_from_bytes.read(delete_at, 4) == sample_bytes[delete_at + delete_len : delete_at + delete_len + 4]

    def test_delete_marks_document_as_modified(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that deleting bytes sets is_modified() to True.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.delete_bytes(0, 1)
        assert sample_doc_from_bytes.is_modified()
