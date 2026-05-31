# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument data transformation operations."""

from __future__ import annotations

import base64
import struct
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    import types

    from intellicrack_hexcore import HexDocument


class TestListTransforms:
    """Tests covering the list_transforms() enumeration API."""

    def test_list_transforms_returns_nonempty_list(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that list_transforms() returns at least one entry.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        transforms: list[tuple[str, str, str]] = sample_doc_from_bytes.list_transforms()
        assert isinstance(transforms, list)
        assert transforms

    def test_list_transforms_each_entry_is_three_tuple(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that every entry returned by list_transforms() is a 3-tuple of strings.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        transforms: list[tuple[str, str, str]] = sample_doc_from_bytes.list_transforms()
        for entry in transforms:
            assert isinstance(entry, tuple)
            assert len(entry) == 3
            t_name: str
            t_category: str
            t_description: str
            t_name, t_category, t_description = entry
            assert isinstance(t_name, str)
            assert isinstance(t_category, str)
            assert isinstance(t_description, str)

    def test_list_transforms_names_are_nonempty_strings(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that all transform names in the list are non-empty strings.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        transforms: list[tuple[str, str, str]] = sample_doc_from_bytes.list_transforms()
        names = [entry[0] for entry in transforms]
        assert all(isinstance(n, str) and len(n) > 0 for n in names)

    def test_list_transforms_contains_base64_encode(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that the base64_encode transform is present in the list.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        transforms: list[tuple[str, str, str]] = sample_doc_from_bytes.list_transforms()
        names = [entry[0] for entry in transforms]
        assert "base64_encode" in names

    def test_list_transforms_contains_base64_decode(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that the base64_decode transform is present in the list.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        transforms: list[tuple[str, str, str]] = sample_doc_from_bytes.list_transforms()
        names = [entry[0] for entry in transforms]
        assert "base64_decode" in names

    def test_list_transforms_contains_xor(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that an XOR transform is present in the list.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        transforms: list[tuple[str, str, str]] = sample_doc_from_bytes.list_transforms()
        names = [entry[0] for entry in transforms]
        assert any("xor" in n.lower() for n in names)

    def test_list_transforms_result_is_consistent_across_calls(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that repeated calls to list_transforms() return the same list.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        first: list[tuple[str, str, str]] = sample_doc_from_bytes.list_transforms()
        second: list[tuple[str, str, str]] = sample_doc_from_bytes.list_transforms()
        assert first == second


class TestBase64Transform:
    """Tests covering base64_encode and base64_decode transforms."""

    def test_base64_encode_returns_valid_base64(self, hexcore: types.ModuleType, sample_bytes: bytes) -> None:
        """Verify that base64_encode produces valid base64 output.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        result = doc.transform_data("base64_encode", 0, 16, {})
        assert isinstance(result, bytes)
        decoded = base64.b64decode(result)
        assert decoded == sample_bytes[:16]

    def test_base64_encode_matches_stdlib_output(self, hexcore: types.ModuleType, sample_bytes: bytes) -> None:
        """Verify that base64_encode output matches Python's standard library result.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        result = doc.transform_data("base64_encode", 0, 32, {})
        expected = base64.b64encode(sample_bytes[:32])
        assert result == expected

    def test_base64_roundtrip(self, hexcore: types.ModuleType, sample_bytes: bytes) -> None:
        """Verify that base64_encode followed by base64_decode reproduces the original data.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        original = sample_bytes[:48]
        doc_src = hexcore.HexDocument.open_bytes(original)
        encoded = doc_src.transform_data("base64_encode", 0, len(original), {})

        doc_enc = hexcore.HexDocument.open_bytes(encoded)
        decoded = doc_enc.transform_data("base64_decode", 0, len(encoded), {})
        assert decoded == original

    def test_base64_encode_at_nonzero_offset(self, hexcore: types.ModuleType, sample_bytes: bytes) -> None:
        """Verify that base64_encode correctly encodes a slice starting at a non-zero offset.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        offset = 32
        length = 16
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        result = doc.transform_data("base64_encode", offset, length, {})
        expected = base64.b64encode(sample_bytes[offset : offset + length])
        assert result == expected


class TestBitwiseTransforms:
    """Tests covering bit_invert and byte_reverse transforms."""

    def test_bit_invert_produces_xor_ff(self, hexcore: types.ModuleType) -> None:
        """Verify that bit_invert XORs every byte with 0xFF.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes([0x00, 0x55, 0xAA, 0xFF])
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("bit_invert", 0, len(input_data), {})
        expected = bytes(b ^ 0xFF for b in input_data)
        assert result == expected

    def test_bit_invert_double_application_is_identity(self, hexcore: types.ModuleType) -> None:
        """Verify that applying bit_invert twice returns the original bytes.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
        doc_src = hexcore.HexDocument.open_bytes(input_data)
        once = doc_src.transform_data("bit_invert", 0, len(input_data), {})
        doc_inv = hexcore.HexDocument.open_bytes(once)
        twice = doc_inv.transform_data("bit_invert", 0, len(once), {})
        assert twice == input_data

    def test_byte_reverse_reverses_bytes(self, hexcore: types.ModuleType) -> None:
        """Verify that byte_reverse produces the mirror of the input.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes([0x01, 0x02, 0x03, 0x04, 0x05])
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("byte_reverse", 0, len(input_data), {})
        assert result == input_data[::-1]

    def test_byte_reverse_double_application_is_identity(self, hexcore: types.ModuleType) -> None:
        """Verify that applying byte_reverse twice returns the original bytes.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes(range(16))
        doc_src = hexcore.HexDocument.open_bytes(input_data)
        once = doc_src.transform_data("byte_reverse", 0, len(input_data), {})
        doc_rev = hexcore.HexDocument.open_bytes(once)
        twice = doc_rev.transform_data("byte_reverse", 0, len(once), {})
        assert twice == input_data


class TestXorTransform:
    """Tests covering the mask_xor transform with single- and multi-byte patterns.

    The native registry exposes XOR masking as ``mask_xor``, which XORs each
    byte with a repeating ``pattern`` parameter. A single-byte pattern is the
    classic single-key XOR.
    """

    def test_xor_single_byte_key_matches_manual(self, hexcore: types.ModuleType) -> None:
        """Verify that mask_xor with a single-byte pattern matches a manual XOR.

        Args:
            hexcore: The native module fixture.
        """
        key_byte = 0xAA
        input_data = bytes(range(16))
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("mask_xor", 0, len(input_data), {"pattern": bytes([key_byte])})
        expected = bytes(b ^ key_byte for b in input_data)
        assert result == expected

    def test_xor_with_zero_key_is_identity(self, hexcore: types.ModuleType) -> None:
        """Verify that mask_xor with a zero pattern leaves the data unchanged.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes(range(32))
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("mask_xor", 0, len(input_data), {"pattern": b"\x00"})
        assert result == input_data

    def test_xor_is_its_own_inverse(self, hexcore: types.ModuleType) -> None:
        """Verify that mask_xor applied twice with the same pattern restores the original data.

        Args:
            hexcore: The native module fixture.
        """
        key_byte = 0x5A
        input_data = bytes(range(16))
        doc_src = hexcore.HexDocument.open_bytes(input_data)
        once = doc_src.transform_data("mask_xor", 0, len(input_data), {"pattern": bytes([key_byte])})
        doc_xored = hexcore.HexDocument.open_bytes(once)
        twice = doc_xored.transform_data("mask_xor", 0, len(once), {"pattern": bytes([key_byte])})
        assert twice == input_data

    def test_xor_at_nonzero_offset(self, hexcore: types.ModuleType) -> None:
        """Verify that mask_xor only processes the specified offset range.

        Args:
            hexcore: The native module fixture.
        """
        key_byte = 0xFF
        input_data = bytes(range(16))
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("mask_xor", 4, 4, {"pattern": bytes([key_byte])})
        expected = bytes(b ^ key_byte for b in input_data[4:8])
        assert result == expected


class TestByteSwapTransforms:
    """Tests covering byte_swap_16 and byte_swap_32 transforms."""

    def test_byte_swap_16_swaps_pairs(self, hexcore: types.ModuleType) -> None:
        """Verify that byte_swap_16 reverses each consecutive pair of bytes.

        Args:
            hexcore: The native module fixture.
        """
        input_data = struct.pack("<HH", 0x1234, 0x5678)
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("byte_swap_16", 0, len(input_data), {})
        expected = struct.pack(">HH", 0x1234, 0x5678)
        assert result == expected

    def test_byte_swap_32_swaps_quads(self, hexcore: types.ModuleType) -> None:
        """Verify that byte_swap_32 reverses each consecutive group of four bytes.

        Args:
            hexcore: The native module fixture.
        """
        input_data = struct.pack("<II", 0xDEADBEEF, 0xCAFEBABE)
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("byte_swap_32", 0, len(input_data), {})
        expected = struct.pack(">II", 0xDEADBEEF, 0xCAFEBABE)
        assert result == expected


class TestTransformEdgeCases:
    """Tests covering edge-case inputs and invalid transform names."""

    def test_invalid_transform_name_raises(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that an unrecognized transform name raises an exception.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        with pytest.raises((OSError, RuntimeError, KeyError, ValueError)):
            sample_doc_from_bytes.transform_data("no_such_transform_xyz_9999", 0, 4, {})

    def test_transform_on_empty_range_returns_empty_bytes(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that a transform applied to length 0 returns empty bytes.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        result = sample_doc_from_bytes.transform_data("base64_encode", 0, 0, {})
        assert result == b""
