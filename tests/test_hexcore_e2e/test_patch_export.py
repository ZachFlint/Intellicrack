# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument IPS/IPS32 patch export and import operations."""

from __future__ import annotations

from typing import Any

import pytest


IPS_HEADER = b"PATCH"
IPS_FOOTER = b"EOF"
IPS32_HEADER = b"IPS32"
IPS32_FOOTER = b"EEOF"

_IPS_HEADER_LEN = 5
_IPS_RECORD_OFFSET_LEN = 3
_IPS_RECORD_SIZE_LEN = 2


class TestGetPatches:
    """Tests covering the get_patches() inspection API."""

    def test_unmodified_doc_returns_empty_patch_list(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that a freshly opened in-memory document has no patches.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        patches: list[tuple[int, bytes]] = sample_doc_from_bytes.get_patches()
        assert isinstance(patches, list)
        assert len(patches) == 0

    def test_write_bytes_produces_patch_entry(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that write_bytes() causes get_patches() to return a non-empty list.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(10, b"\xAA\xBB\xCC\xDD")
        patches: list[tuple[int, bytes]] = sample_doc_from_bytes.get_patches()
        assert len(patches) > 0

    def test_patch_entry_has_correct_offset_and_data(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that the patch entry records the correct offset and written bytes.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        payload = b"\xDE\xAD\xBE\xEF"
        offset = 20
        sample_doc_from_bytes.write_bytes(offset, payload)
        patches: list[tuple[int, bytes]] = sample_doc_from_bytes.get_patches()
        offsets_and_data = {p[0]: p[1] for p in patches}
        assert offset in offsets_and_data
        assert offsets_and_data[offset] == payload

    def test_patch_list_entries_are_two_tuples(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that every patch entry is a 2-tuple of (int, bytes).

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(5, b"\x01\x02")
        patches: list[tuple[int, bytes]] = sample_doc_from_bytes.get_patches()
        for entry in patches:
            assert isinstance(entry, tuple)
            assert len(entry) == 2
            assert isinstance(entry[0], int)
            assert isinstance(entry[1], bytes)


class TestIPSExport:
    """Tests covering export_patches_ips() format validity."""

    def test_ips_export_starts_with_patch_magic(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that the IPS blob begins with the 'PATCH' magic header.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\xFF\x00\xFF\x00")
        ips_data = sample_doc_from_bytes.export_patches_ips()
        assert ips_data[:_IPS_HEADER_LEN] == IPS_HEADER

    def test_ips_export_ends_with_eof_magic(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that the IPS blob ends with the 'EOF' magic footer.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\xAA\xBB")
        ips_data = sample_doc_from_bytes.export_patches_ips()
        assert ips_data[-3:] == IPS_FOOTER

    def test_ips_export_returns_bytes(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that export_patches_ips() returns a bytes object.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\x42")
        result = sample_doc_from_bytes.export_patches_ips()
        assert isinstance(result, bytes)

    def test_ips_export_minimum_size_with_one_patch(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that a one-byte patch produces an IPS blob of at least 11 bytes.

        The minimum IPS blob is: 5 (header) + 3 (offset) + 2 (size) + 1 (data) + 3 (EOF) = 14.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\x99")
        ips_data: bytes = sample_doc_from_bytes.export_patches_ips()
        assert len(ips_data) >= _IPS_HEADER_LEN + _IPS_RECORD_OFFSET_LEN + _IPS_RECORD_SIZE_LEN + 1 + 3


class TestIPS32Export:
    """Tests covering export_patches_ips32() format validity."""

    def test_ips32_export_starts_with_ips32_magic(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that the IPS32 blob begins with the 'IPS32' magic header.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\x01\x02\x03\x04")
        ips32_data = sample_doc_from_bytes.export_patches_ips32()
        assert ips32_data[:5] == IPS32_HEADER

    def test_ips32_export_ends_with_eeof_magic(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that the IPS32 blob ends with the 'EEOF' magic footer.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\xCA\xFE\xBA\xBE")
        ips32_data = sample_doc_from_bytes.export_patches_ips32()
        assert ips32_data[-4:] == IPS32_FOOTER

    def test_ips32_export_returns_bytes(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that export_patches_ips32() returns a bytes object.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(8, b"\x11\x22")
        result = sample_doc_from_bytes.export_patches_ips32()
        assert isinstance(result, bytes)


class TestIPSRoundtrip:
    """Tests covering export then import of IPS patches produces equivalent data."""

    def test_ips_roundtrip_single_patch(
        self, hexcore: Any, sample_bytes: bytes
    ) -> None:
        """Verify that an IPS export/import cycle reproduces the patched document content.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc_modified = hexcore.HexDocument.open_bytes(sample_bytes)
        patch_offset = 10
        patch_data = b"\xDE\xAD\xBE\xEF"
        doc_modified.write_bytes(patch_offset, patch_data)
        ips_data = doc_modified.export_patches_ips()

        doc_target = hexcore.HexDocument.open_bytes(sample_bytes)
        count = doc_target.import_patches_ips(ips_data)
        assert count > 0
        assert doc_target.read(patch_offset, len(patch_data)) == patch_data

    def test_ips_roundtrip_preserves_unpatched_bytes(
        self, hexcore: Any, sample_bytes: bytes
    ) -> None:
        """Verify that bytes outside the patched range are unchanged after IPS import.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc_modified = hexcore.HexDocument.open_bytes(sample_bytes)
        patch_offset = 50
        patch_data = b"\xFF\xFF"
        doc_modified.write_bytes(patch_offset, patch_data)
        ips_data = doc_modified.export_patches_ips()

        doc_target = hexcore.HexDocument.open_bytes(sample_bytes)
        doc_target.import_patches_ips(ips_data)
        assert doc_target.read(0, 10) == sample_bytes[:10]
        assert doc_target.read(100, 10) == sample_bytes[100:110]

    def test_ips_roundtrip_multi_patch(
        self, hexcore: Any, sample_bytes: bytes
    ) -> None:
        """Verify that multiple disjoint patches survive an IPS export/import cycle.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc_modified = hexcore.HexDocument.open_bytes(sample_bytes)
        patches: list[tuple[int, bytes]] = [
            (0, b"\xAA\xBB"),
            (100, b"\xCC\xDD\xEE"),
            (200, b"\x11"),
        ]
        for off, data in patches:
            doc_modified.write_bytes(off, data)
        ips_data = doc_modified.export_patches_ips()

        doc_target = hexcore.HexDocument.open_bytes(sample_bytes)
        doc_target.import_patches_ips(ips_data)
        for off, data in patches:
            assert doc_target.read(off, len(data)) == data


class TestIPSImport:
    """Tests covering import_patches_ips() return value and data application."""

    def test_import_ips_returns_patch_count(
        self, hexcore: Any, sample_bytes: bytes
    ) -> None:
        """Verify that import_patches_ips() returns the number of records applied.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc_src = hexcore.HexDocument.open_bytes(sample_bytes)
        doc_src.write_bytes(0, b"\xAA\xBB\xCC")
        ips_data = doc_src.export_patches_ips()

        doc_dst = hexcore.HexDocument.open_bytes(sample_bytes)
        count = doc_dst.import_patches_ips(ips_data)
        assert isinstance(count, int)
        assert count >= 1

    def test_import_ips_raises_on_invalid_data(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that import_patches_ips() raises an exception for malformed input.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        with pytest.raises((OSError, RuntimeError, ValueError)):
            sample_doc_from_bytes.import_patches_ips(b"\x00\x01\x02\x03")
