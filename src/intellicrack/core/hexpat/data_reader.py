# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
# This file is part of Intellicrack. See LICENSE for details.
"""Byte-access abstraction over HexDocument or raw bytes for the .hexpat interpreter."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from intellicrack.core.hexpat.errors import HexPatRuntimeError


if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Literal

    from intellicrack.core.types import HexDocumentLike


class DataReader:
    """Provides typed byte access to binary data for pattern evaluation.

    Wraps either a HexDocument PyO3 object or raw bytes behind a uniform
    read interface used by the HexPat evaluator.

    Args:
        read_fn: A callable ``(offset, length) -> bytes`` that returns
            the requested byte slice from the underlying data source.
        length: Total number of bytes available in the data source.
    """

    def __init__(self, read_fn: Callable[[int, int], bytes], length: int) -> None:
        self._read_fn = read_fn
        self._length = length

    @staticmethod
    def from_document(document: HexDocumentLike) -> DataReader:
        """Create a DataReader from a HexDocument PyO3 object.

        The document is expected to expose ``read(offset, length) -> list[int]``
        and ``length() -> int`` methods as provided by the Rust/PyO3 binding.

        Args:
            document: A HexDocument PyO3 object with ``read`` and ``length``
                methods.

        Returns:
            DataReader: A DataReader backed by the supplied HexDocument.
        """
        doc_read = document.read
        doc_length = document.length

        def read_fn(offset: int, length: int) -> bytes:
            raw: list[int] = doc_read(offset, length)
            return bytes(raw)

        return DataReader(read_fn, doc_length())

    @staticmethod
    def from_bytes(data: bytes) -> DataReader:
        """Create a DataReader from raw bytes.

        Args:
            data: The raw binary data to wrap.

        Returns:
            DataReader: A DataReader backed by the supplied bytes object.
        """

        def read_fn(offset: int, length: int) -> bytes:
            return data[offset : offset + length]

        return DataReader(read_fn, len(data))

    @property
    def size(self) -> int:
        """Total number of bytes available in the data source.

        Returns:
            int: The length of the underlying data in bytes.
        """
        return self._length

    def read(self, offset: int, length: int) -> bytes:
        """Read a raw byte slice from the data source.

        Args:
            offset: Zero-based byte offset to start reading from.
            length: Number of bytes to read.

        Returns:
            bytes: A bytes object of exactly ``length`` bytes starting at ``offset``.

        Raises:
            HexPatRuntimeError: If ``offset`` is negative or the requested
                range exceeds the data source length.
        """
        if offset < 0 or offset + length > self._length:
            msg = f"read out of bounds: offset={offset}, length={length}, data_size={self._length}"
            raise HexPatRuntimeError(msg, offset=offset)
        return self._read_fn(offset, length)

    def read_u8(self, offset: int) -> int:
        """Read an unsigned 8-bit integer.

        Args:
            offset: Zero-based byte offset.

        Returns:
            int: An unsigned integer in the range [0, 255].
        """
        (value,) = struct.unpack("B", self.read(offset, 1))
        return int(value)

    def read_u16(self, offset: int, endian: str = "little") -> int:
        """Read an unsigned 16-bit integer.

        Args:
            offset: Zero-based byte offset.
            endian: Byte order — ``"little"`` (default) or ``"big"``.

        Returns:
            int: An unsigned integer in the range [0, 65535].
        """
        prefix = "<" if endian == "little" else ">"
        (value,) = struct.unpack(f"{prefix}H", self.read(offset, 2))
        return int(value)

    def read_u32(self, offset: int, endian: str = "little") -> int:
        """Read an unsigned 32-bit integer.

        Args:
            offset: Zero-based byte offset.
            endian: Byte order — ``"little"`` (default) or ``"big"``.

        Returns:
            int: An unsigned integer in the range [0, 2**32-1].
        """
        prefix = "<" if endian == "little" else ">"
        (value,) = struct.unpack(f"{prefix}I", self.read(offset, 4))
        return int(value)

    def read_u64(self, offset: int, endian: str = "little") -> int:
        """Read an unsigned 64-bit integer.

        Args:
            offset: Zero-based byte offset.
            endian: Byte order — ``"little"`` (default) or ``"big"``.

        Returns:
            int: An unsigned integer in the range [0, 2**64-1].
        """
        prefix = "<" if endian == "little" else ">"
        (value,) = struct.unpack(f"{prefix}Q", self.read(offset, 8))
        return int(value)

    def read_u128(self, offset: int, endian: str = "little") -> int:
        """Read an unsigned 128-bit integer.

        Args:
            offset: Zero-based byte offset.
            endian: Byte order — ``"little"`` (default) or ``"big"``.

        Returns:
            int: An unsigned integer in the range [0, 2**128-1].
        """
        raw = self.read(offset, 16)
        byteorder: Literal["little", "big"] = "little" if endian != "big" else "big"
        return int.from_bytes(raw, byteorder=byteorder, signed=False)

    def read_s8(self, offset: int) -> int:
        """Read a signed 8-bit integer.

        Args:
            offset: Zero-based byte offset.

        Returns:
            int: A signed integer in the range [-128, 127].
        """
        (value,) = struct.unpack("b", self.read(offset, 1))
        return int(value)

    def read_s16(self, offset: int, endian: str = "little") -> int:
        """Read a signed 16-bit integer.

        Args:
            offset: Zero-based byte offset.
            endian: Byte order — ``"little"`` (default) or ``"big"``.

        Returns:
            int: A signed integer in the range [-32768, 32767].
        """
        prefix = "<" if endian == "little" else ">"
        (value,) = struct.unpack(f"{prefix}h", self.read(offset, 2))
        return int(value)

    def read_s32(self, offset: int, endian: str = "little") -> int:
        """Read a signed 32-bit integer.

        Args:
            offset: Zero-based byte offset.
            endian: Byte order — ``"little"`` (default) or ``"big"``.

        Returns:
            int: A signed integer in the range [-2**31, 2**31-1].
        """
        prefix = "<" if endian == "little" else ">"
        (value,) = struct.unpack(f"{prefix}i", self.read(offset, 4))
        return int(value)

    def read_s64(self, offset: int, endian: str = "little") -> int:
        """Read a signed 64-bit integer.

        Args:
            offset: Zero-based byte offset.
            endian: Byte order — ``"little"`` (default) or ``"big"``.

        Returns:
            int: A signed integer in the range [-2**63, 2**63-1].
        """
        prefix = "<" if endian == "little" else ">"
        (value,) = struct.unpack(f"{prefix}q", self.read(offset, 8))
        return int(value)

    def read_s128(self, offset: int, endian: str = "little") -> int:
        """Read a signed 128-bit integer.

        Args:
            offset: Zero-based byte offset.
            endian: Byte order — ``"little"`` (default) or ``"big"``.

        Returns:
            int: A signed integer in the range [-2**127, 2**127-1].
        """
        raw = self.read(offset, 16)
        byteorder: Literal["little", "big"] = "little" if endian != "big" else "big"
        return int.from_bytes(raw, byteorder=byteorder, signed=True)

    def read_float(self, offset: int, endian: str = "little") -> float:
        """Read an IEEE 754 single-precision (32-bit) float.

        Args:
            offset: Zero-based byte offset.
            endian: Byte order — ``"little"`` (default) or ``"big"``.

        Returns:
            float: A Python float parsed as a 32-bit IEEE 754 value.
        """
        prefix = "<" if endian == "little" else ">"
        (value,) = struct.unpack(f"{prefix}f", self.read(offset, 4))
        return float(value)

    def read_double(self, offset: int, endian: str = "little") -> float:
        """Read an IEEE 754 double-precision (64-bit) float.

        Args:
            offset: Zero-based byte offset.
            endian: Byte order — ``"little"`` (default) or ``"big"``.

        Returns:
            float: A Python float parsed as a 64-bit IEEE 754 value.
        """
        prefix = "<" if endian == "little" else ">"
        (value,) = struct.unpack(f"{prefix}d", self.read(offset, 8))
        return float(value)

    def read_char(self, offset: int) -> str:
        """Read a single ASCII character (1 byte).

        Non-ASCII bytes are replaced with the Unicode replacement character
        (U+FFFD) using the ``"replace"`` error handler.

        Args:
            offset: Zero-based byte offset.

        Returns:
            str: A single-character string decoded as ASCII.
        """
        raw = self.read(offset, 1)
        return raw.decode("ascii", errors="replace")

    def read_char16(self, offset: int, endian: str = "little") -> str:
        """Read a single UTF-16 character (2 bytes).

        Args:
            offset: Zero-based byte offset.
            endian: Byte order — ``"little"`` (default) or ``"big"``.

        Returns:
            str: A single-character string decoded as UTF-16.
        """
        raw = self.read(offset, 2)
        encoding = "utf-16-le" if endian == "little" else "utf-16-be"
        return raw.decode(encoding, errors="replace")

    def read_bool(self, offset: int) -> bool:
        """Read a boolean value from a single byte.

        A non-zero byte is ``True``; a zero byte is ``False``.

        Args:
            offset: Zero-based byte offset.

        Returns:
            bool: ``True`` if the byte is non-zero, ``False`` otherwise.
        """
        return self.read_u8(offset) != 0

    def read_string(self, offset: int, max_length: int = 4096) -> tuple[str, int]:
        """Read a null-terminated UTF-8 string.

        Scans forward from ``offset`` for a NUL byte (``0x00``), stopping
        after at most ``max_length`` bytes. Decoding uses ``"replace"`` for
        any invalid UTF-8 sequences.

        Args:
            offset: Zero-based byte offset at which the string begins.
            max_length: Maximum number of bytes to scan before giving up.
                Defaults to 4096.

        Returns:
            tuple[str, int]: A tuple of ``(decoded_string, bytes_consumed)``
                where ``bytes_consumed`` includes the terminating NUL byte.
        """
        read_len = min(max_length, self._length - offset)
        chunk = self.read(offset, read_len)
        nul_pos = chunk.find(b"\x00")
        if nul_pos == -1:
            return chunk.decode("utf-8", errors="replace"), read_len
        return chunk[:nul_pos].decode("utf-8", errors="replace"), nul_pos + 1

    def read_fixed_string(self, offset: int, length: int) -> str:
        """Read a fixed-length byte sequence and decode it as UTF-8.

        Trailing NUL bytes are stripped before decoding.

        Args:
            offset: Zero-based byte offset.
            length: Number of bytes to read.

        Returns:
            str: A string decoded from the fixed-length byte range with
                trailing NUL bytes removed.
        """
        raw = self.read(offset, length)
        return raw.rstrip(b"\x00").decode("utf-8", errors="replace")

    def find_sequence(self, pattern: bytes, start: int = 0) -> int:
        """Search for a byte sequence starting from a given offset.

        Performs a linear scan over the data source in chunks of 65536 bytes,
        with sufficient overlap to detect patterns that straddle chunk
        boundaries.

        Args:
            pattern: The byte sequence to search for.
            start: Zero-based byte offset at which to begin the search.
                Defaults to 0.

        Returns:
            int: The zero-based byte offset of the first occurrence of
                ``pattern`` at or after ``start``, or ``-1`` if not found.
        """
        chunk_size = 65536
        pat_len = len(pattern)
        pos = start
        while pos + pat_len <= self._length:
            read_len = min(chunk_size + pat_len - 1, self._length - pos)
            chunk = self.read(pos, read_len)
            idx = chunk.find(pattern)
            if idx >= 0:
                return pos + idx
            pos += chunk_size
        return -1
