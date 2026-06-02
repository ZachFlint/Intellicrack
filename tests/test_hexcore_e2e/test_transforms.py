# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument data transformation operations.

These tests drive the real ``intellicrack_hexcore`` native transform registry
end to end against real byte payloads. Expected values come from independent
oracles (Python's ``base64`` standard library and hand-verified constants),
never from the implementation's own output.
"""

from __future__ import annotations

import base64
import struct
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    import types

    from intellicrack_hexcore import HexDocument


EXPECTED_TRANSFORM_REGISTRY: dict[str, tuple[str, str]] = {
    "base64_encode": ("encoding", "Base64 encode"),
    "base64_decode": ("encoding", "Base64 decode"),
    "bit_invert": ("bitops", "Bitwise NOT each byte"),
    "byte_reverse": ("byteops", "Reverse byte order"),
    "byte_swap_16": ("byteops", "Swap endianness of 16-bit words"),
    "byte_swap_32": ("byteops", "Swap endianness of 32-bit words"),
    "mask_xor": ("mask", "XOR each byte with repeating pattern"),
}


class TestListTransforms:
    """Tests covering the list_transforms() enumeration API."""

    def test_known_transforms_have_exact_category_and_description(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify each known transform reports its exact category and description.

        The expected category/description pairs are an independent specification
        of the registry, not copied from the implementation's output. If a
        transform were renamed, recategorised, or had its description silently
        changed, the field-by-field comparison would fail.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        transforms: list[tuple[str, str, str]] = sample_doc_from_bytes.list_transforms()
        registry: dict[str, tuple[str, str]] = {name: (category, description) for name, category, description in transforms}
        for name, (expected_category, expected_description) in EXPECTED_TRANSFORM_REGISTRY.items():
            assert name in registry, f"transform {name!r} missing from registry"
            assert registry[name] == (expected_category, expected_description)

    def test_transform_names_are_unique(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that every transform name in the registry is unique.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        transforms: list[tuple[str, str, str]] = sample_doc_from_bytes.list_transforms()
        names: list[str] = [name for name, _category, _description in transforms]
        assert len(names) == len(set(names)), "duplicate transform names present"

    def test_every_entry_is_three_nonempty_string_fields(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify every registry entry is a 3-tuple of non-empty strings.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        transforms: list[tuple[str, str, str]] = sample_doc_from_bytes.list_transforms()
        assert transforms, "registry must not be empty"
        for entry in transforms:
            assert len(entry) == 3
            name, category, description = entry
            assert all(isinstance(field, str) for field in (name, category, description))
            assert len(name) > 0
            assert len(category) > 0
            assert len(description) > 0

    def test_listed_byte_transforms_actually_execute(self, hexcore: types.ModuleType, sample_doc_from_bytes: HexDocument) -> None:
        """Verify listed parameterless byte transforms run and change data correctly.

        Confirms the names returned by ``list_transforms()`` correspond to real,
        working transforms (not arbitrary strings) by executing a representative
        set against a known payload and checking each against an independent
        expected value.

        Args:
            hexcore: The native module fixture.
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        listed: set[str] = {name for name, _category, _description in sample_doc_from_bytes.list_transforms()}
        payload = bytes([0x10, 0x20, 0x30, 0x40])
        expectations: dict[str, bytes] = {
            "bit_invert": bytes([0xEF, 0xDF, 0xCF, 0xBF]),
            "byte_reverse": bytes([0x40, 0x30, 0x20, 0x10]),
            "base64_encode": base64.b64encode(payload),
        }
        for name, expected in expectations.items():
            assert name in listed, f"{name!r} not advertised by list_transforms()"
            doc = hexcore.HexDocument.open_bytes(payload)
            result = doc.transform_data(name, 0, len(payload), {})
            assert result == expected, f"transform {name!r} produced {result!r}, expected {expected!r}"

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
        """Verify base64_encode on a non-zero offset slice against stdlib and round-trip.

        Uses Python's ``base64.b64encode`` as the independent oracle for the
        exact output, then decodes the native result with ``base64.b64decode``
        and asserts it reproduces precisely the requested input slice.

        Args:
            hexcore: The native module fixture.
            sample_bytes: The 256-byte payload fixture.
        """
        offset = 32
        length = 16
        expected_slice = sample_bytes[offset : offset + length]
        doc = hexcore.HexDocument.open_bytes(sample_bytes)
        result = doc.transform_data("base64_encode", offset, length, {})
        assert result == base64.b64encode(expected_slice)
        assert base64.b64decode(result) == expected_slice


class TestBitwiseTransforms:
    """Tests covering bit_invert and byte_reverse transforms."""

    def test_bit_invert_matches_precomputed_constant(self, hexcore: types.ModuleType) -> None:
        """Verify bit_invert against a hand-verified expected constant.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes([0x00, 0x55, 0xAA, 0xFF])
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("bit_invert", 0, len(input_data), {})
        assert result == bytes([0xFF, 0xAA, 0x55, 0x00])

    def test_bit_invert_double_application_is_identity(self, hexcore: types.ModuleType) -> None:
        """Verify that applying bit_invert twice returns the original bytes.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
        doc_src = hexcore.HexDocument.open_bytes(input_data)
        once = doc_src.transform_data("bit_invert", 0, len(input_data), {})
        assert once == bytes([0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21, 0x0F])
        doc_inv = hexcore.HexDocument.open_bytes(once)
        twice = doc_inv.transform_data("bit_invert", 0, len(once), {})
        assert twice == input_data

    def test_byte_reverse_matches_precomputed_constant(self, hexcore: types.ModuleType) -> None:
        """Verify byte_reverse against a hand-verified mirror constant.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes([0x01, 0x02, 0x03, 0x04, 0x05])
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("byte_reverse", 0, len(input_data), {})
        assert result == bytes([0x05, 0x04, 0x03, 0x02, 0x01])

    def test_byte_reverse_double_application_is_identity(self, hexcore: types.ModuleType) -> None:
        """Verify that applying byte_reverse twice returns the original bytes.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes(range(16))
        doc_src = hexcore.HexDocument.open_bytes(input_data)
        once = doc_src.transform_data("byte_reverse", 0, len(input_data), {})
        assert once == bytes(reversed(range(16)))
        doc_rev = hexcore.HexDocument.open_bytes(once)
        twice = doc_rev.transform_data("byte_reverse", 0, len(once), {})
        assert twice == input_data


class TestXorTransform:
    """Tests covering the mask_xor transform with single- and multi-byte patterns.

    The native registry exposes XOR masking as ``mask_xor``, which XORs each
    byte with a repeating ``pattern`` parameter. A single-byte pattern is the
    classic single-key XOR.
    """

    def test_xor_single_byte_key_matches_precomputed_constant(self, hexcore: types.ModuleType) -> None:
        """Verify mask_xor with a single-byte pattern against a hand-verified constant.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes([0x00, 0x0F, 0xF0, 0xFF])
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("mask_xor", 0, len(input_data), {"pattern": bytes([0xAA])})
        assert result == bytes([0xAA, 0xA5, 0x5A, 0x55])

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

    def test_xor_at_nonzero_offset_matches_precomputed_constant(self, hexcore: types.ModuleType) -> None:
        """Verify mask_xor processes only the offset range against a hand-verified constant.

        The input is ``bytes(range(16))``; bytes 4..7 are ``04 05 06 07`` which,
        XORed with ``0xFF``, give the independently hand-computed constant
        ``FB FA F9 F8``. The expected value is a precomputed literal, not an
        inline re-implementation of the production XOR loop.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes(range(16))
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("mask_xor", 4, 4, {"pattern": bytes([0xFF])})
        assert result == bytes([0xFB, 0xFA, 0xF9, 0xF8])

    def test_xor_multibyte_pattern_matches_precomputed_constant(self, hexcore: types.ModuleType) -> None:
        """Verify mask_xor with a repeating multi-byte pattern against a hand-verified constant.

        ``bytes(range(8))`` XORed with the repeating pattern ``DE AD BE EF`` is
        the independently hand-computed constant below.

        Args:
            hexcore: The native module fixture.
        """
        input_data = bytes(range(8))
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("mask_xor", 0, len(input_data), {"pattern": bytes([0xDE, 0xAD, 0xBE, 0xEF])})
        assert result == bytes([0xDE, 0xAC, 0xBC, 0xEC, 0xDA, 0xA8, 0xB8, 0xE8])


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
        assert result == bytes([0x12, 0x34, 0x56, 0x78])

    def test_byte_swap_32_swaps_quads(self, hexcore: types.ModuleType) -> None:
        """Verify that byte_swap_32 reverses each consecutive group of four bytes.

        Args:
            hexcore: The native module fixture.
        """
        input_data = struct.pack("<II", 0xDEADBEEF, 0xCAFEBABE)
        doc = hexcore.HexDocument.open_bytes(input_data)
        result = doc.transform_data("byte_swap_32", 0, len(input_data), {})
        assert result == bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])


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
