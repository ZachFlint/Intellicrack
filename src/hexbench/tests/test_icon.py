# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gates for the packaged Hexbench application icon.

``hexbench.spec`` embeds ``hexbench.ico`` into the executable, and the
``build-hexbench`` recipe points the project-root shortcut at that executable,
so a malformed or truncated icon reaches the shell as a broken launcher. These
tests parse the shipped file with the standard library only and check the
structure Windows relies on: a well-formed directory, one entry per declared
size, headers that agree with their directory entries, and payloads that are
fully contained in the file.

The parser here is deliberately independent of the generator in
``scripts/make_hexbench_icon.py``. It decodes the bytes on disk rather than
re-deriving them from the same constants, so a generator regression shows up as
a failure instead of being reproduced identically on both sides of the
comparison.
"""

from __future__ import annotations

import struct
import unittest
from pathlib import Path
from typing import Final

from ._support import Assertions


_PACKAGE_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
_ICON_PATH: Final[Path] = _PACKAGE_ROOT / "hexbench.ico"
_SPEC_PATH: Final[Path] = _PACKAGE_ROOT / "hexbench.spec"

_ICONDIR: Final[struct.Struct] = struct.Struct("<HHH")
_ICONDIRENTRY: Final[struct.Struct] = struct.Struct("<BBBBHHII")
_BITMAPINFOHEADER: Final[struct.Struct] = struct.Struct("<IiiHHIIiiII")

_ICONDIR_SIZE: Final[int] = 6
_ICONDIRENTRY_SIZE: Final[int] = 16
_ICO_RESOURCE_TYPE: Final[int] = 1
_DIB_HEADER_SIZE: Final[int] = 40
_EXPECTED_BPP: Final[int] = 32
_MAX_DIRECTORY_DIMENSION: Final[int] = 256
_MASK_ALIGNMENT_BITS: Final[int] = 31
_MASK_BITS_PER_WORD: Final[int] = 32
_BYTES_PER_PIXEL: Final[int] = 4
_PNG_IHDR_OFFSET: Final[int] = 16
_PNG_SIGNATURE: Final[bytes] = b"\x89PNG\r\n\x1a\n"

_EXPECTED_SIZES: Final[tuple[int, ...]] = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)
_SHELL_CRITICAL_SIZES: Final[tuple[int, ...]] = (16, 32, 48, 256)
_SPEC_ICON_REFERENCE: Final[str] = 'icon=str(PACKAGE_ROOT / "hexbench.ico")'


class _Entry:
    """One decoded ``ICONDIRENTRY`` together with its payload."""

    def __init__(self, declared: int, payload: bytes) -> None:
        """Store the declared edge length and the entry's raw bytes.

        Args:
            declared: Edge length from the directory, where ``0`` means 256.
            payload: The entry's image data.
        """
        self.size: int = _MAX_DIRECTORY_DIMENSION if declared == 0 else declared
        self.payload: bytes = payload

    @property
    def is_png(self) -> bool:
        """Whether the payload is PNG-compressed rather than a classic DIB.

        Returns:
            bool: ``True`` when the payload opens with a PNG signature.
        """
        return self.payload.startswith(_PNG_SIGNATURE)


def _parse(data: bytes) -> list[_Entry]:
    """Decode an ICO file into its entries.

    Args:
        data: Complete ``.ico`` file contents.

    Returns:
        list[_Entry]: The decoded entries, in directory order.

    Raises:
        AssertionError: If the header is not a valid icon directory, or an
            entry's payload runs past the end of the file.
    """
    reserved, resource_type, count = _ICONDIR.unpack_from(data, 0)
    if reserved != 0 or resource_type != _ICO_RESOURCE_TYPE or count == 0:
        message = f"not an icon directory: reserved={reserved} type={resource_type} count={count}"
        raise AssertionError(message)

    entries: list[_Entry] = []
    for index in range(count):
        offset = _ICONDIR_SIZE + index * _ICONDIRENTRY_SIZE
        unpacked = _ICONDIRENTRY.unpack_from(data, offset)
        declared_width = int(unpacked[0])
        length = int(unpacked[6])
        data_offset = int(unpacked[7])
        end = data_offset + length
        if end > len(data):
            message = f"entry {index} payload ends at {end}, past the {len(data)}-byte file"
            raise AssertionError(message)
        entries.append(_Entry(declared_width, data[data_offset:end]))
    return entries


def _mask_bytes(size: int) -> int:
    """Return the padded byte count of an icon's 1-bit AND mask.

    Args:
        size: Edge length of the icon in pixels.

    Returns:
        int: Mask size in bytes, each row padded to a 4-byte boundary.
    """
    stride = ((size + _MASK_ALIGNMENT_BITS) // _MASK_BITS_PER_WORD) * 4
    return stride * size


class IconFileTests(Assertions, unittest.TestCase):
    """Structural gates for the icon shipped beside the spec."""

    data: bytes
    entries: list[_Entry]

    @classmethod
    def setUpClass(cls) -> None:
        """Read and decode the shipped icon once for the whole class."""
        cls.data = _ICON_PATH.read_bytes()
        cls.entries = _parse(cls.data)

    def test_icon_ships_beside_the_spec(self) -> None:
        """The icon the spec embeds must exist and carry real payloads."""
        self.truthy(_ICON_PATH.is_file(), f"icon file at {_ICON_PATH}")
        self.exceeds(len(self.data), _ICONDIR_SIZE + _ICONDIRENTRY_SIZE, "icon file size")

    def test_spec_embeds_this_icon(self) -> None:
        """``hexbench.spec`` must point ``icon=`` at the shipped file."""
        spec = _SPEC_PATH.read_text(encoding="utf-8")
        self.require(_SPEC_ICON_REFERENCE in spec, f"hexbench.spec must contain {_SPEC_ICON_REFERENCE}")

    def test_every_expected_size_is_present(self) -> None:
        """The icon must carry exactly the declared size ladder."""
        observed = tuple(sorted(entry.size for entry in self.entries))
        self.equal(observed, tuple(sorted(_EXPECTED_SIZES)), "icon size ladder")

    def test_shell_critical_sizes_are_present(self) -> None:
        """The sizes Windows actually requests must all be real entries."""
        present = [entry.size for entry in self.entries]
        for size in _SHELL_CRITICAL_SIZES:
            self.contains(size, present, f"{size}px shell entry")

    def test_entries_are_unique_and_ascending(self) -> None:
        """Duplicate or unordered entries make the shell pick unpredictably."""
        sizes = [entry.size for entry in self.entries]
        self.equal(len(set(sizes)), len(sizes), f"distinct entry sizes in {sizes}")
        self.equal(sizes, sorted(sizes), "entry ordering")

    def test_dib_headers_agree_with_their_directory_entry(self) -> None:
        """Each DIB must declare its own size and the doubled mask height."""
        checked = 0
        for entry in self.entries:
            if entry.is_png:
                continue
            header = _BITMAPINFOHEADER.unpack_from(entry.payload, 0)
            self.equal(int(header[0]), _DIB_HEADER_SIZE, f"{entry.size}px header size")
            self.equal(int(header[1]), entry.size, f"{entry.size}px DIB width")
            self.equal(int(header[2]), entry.size * 2, f"{entry.size}px DIB height with mask")
            self.equal(int(header[3]), 1, f"{entry.size}px colour planes")
            self.equal(int(header[4]), _EXPECTED_BPP, f"{entry.size}px bit depth")
            checked += 1
        self.exceeds(checked, 0, "DIB entries examined")

    def test_dib_payloads_carry_a_full_bitmap_and_mask(self) -> None:
        """A truncated DIB renders as garbage, so the byte count must match."""
        for entry in self.entries:
            if entry.is_png:
                continue
            pixels = entry.size * entry.size * _BYTES_PER_PIXEL
            expected = _DIB_HEADER_SIZE + pixels + _mask_bytes(entry.size)
            self.equal(len(entry.payload), expected, f"{entry.size}px payload length")

    def test_largest_entry_is_png_compressed(self) -> None:
        """The 256px entry must be PNG, as Windows Vista and later expect."""
        largest = max(self.entries, key=lambda entry: entry.size)
        self.equal(largest.size, _MAX_DIRECTORY_DIMENSION, "largest entry size")
        self.truthy(largest.is_png, "256px entry PNG compression")

    def test_png_entry_declares_its_real_dimensions(self) -> None:
        """A PNG payload's IHDR must match the size the directory advertises."""
        checked = 0
        for entry in self.entries:
            if not entry.is_png:
                continue
            width, height = struct.unpack_from(">II", entry.payload, _PNG_IHDR_OFFSET)
            self.equal((int(width), int(height)), (entry.size, entry.size), f"{entry.size}px IHDR")
            checked += 1
        self.exceeds(checked, 0, "PNG entries examined")

    def test_sizes_are_rendered_independently(self) -> None:
        """Entries must not be clones of one master image.

        A generator that rendered once and stored the same pixels under several
        directory entries would still parse cleanly, so the payloads themselves
        are compared: every entry has to be distinct.
        """
        payloads = [entry.payload for entry in self.entries]
        self.equal(len(set(payloads)), len(payloads), "distinct entry payloads")


if __name__ == "__main__":
    unittest.main()
