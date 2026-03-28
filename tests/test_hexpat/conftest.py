# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""Shared fixtures for hexpat interpreter tests."""

from __future__ import annotations

import struct

import pytest

from intellicrack.core.hexpat.interpreter import HexPatInterpreter


@pytest.fixture
def interp() -> HexPatInterpreter:
    """Provide a fresh HexPatInterpreter instance."""
    return HexPatInterpreter()


@pytest.fixture
def pe_header_bytes() -> bytes:
    """Build a minimal PE file header (128 bytes) with valid DOS + PE structures."""
    data = bytearray(128)
    data[0:2] = b"MZ"
    struct.pack_into("<H", data, 2, 0x0090)
    struct.pack_into("<I", data, 60, 0x50)
    data[0x50:0x54] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x54, 0x8664)
    struct.pack_into("<H", data, 0x56, 3)
    struct.pack_into("<I", data, 0x58, 0)
    return bytes(data)


@pytest.fixture
def elf_header_bytes() -> bytes:
    """Build a minimal 64-bit ELF header (64 bytes)."""
    data = bytearray(64)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<H", data, 16, 3)
    struct.pack_into("<H", data, 18, 0x3E)
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<Q", data, 24, 0x1000)
    struct.pack_into("<Q", data, 32, 0x40)
    return bytes(data)


@pytest.fixture
def bmp_header_bytes() -> bytes:
    """Build a minimal 24-bit BMP file (1x1 pixel, 58 bytes)."""
    data = bytearray(58)
    data[0:2] = b"BM"
    struct.pack_into("<I", data, 2, 58)
    struct.pack_into("<I", data, 10, 54)
    struct.pack_into("<I", data, 14, 40)
    struct.pack_into("<i", data, 18, 1)
    struct.pack_into("<i", data, 22, 1)
    struct.pack_into("<H", data, 26, 1)
    struct.pack_into("<H", data, 28, 24)
    struct.pack_into("<I", data, 30, 0)
    data[54:57] = b"\xff\x00\x00"
    return bytes(data)


@pytest.fixture
def zip_local_header_bytes() -> bytes:
    """Build a minimal ZIP local file header."""
    data = bytearray(64)
    data[0:4] = b"PK\x03\x04"
    struct.pack_into("<H", data, 4, 20)
    struct.pack_into("<H", data, 6, 0)
    struct.pack_into("<H", data, 8, 0)
    struct.pack_into("<H", data, 10, 0)
    struct.pack_into("<H", data, 12, 0)
    struct.pack_into("<I", data, 14, 0xAABBCCDD)
    struct.pack_into("<I", data, 18, 10)
    struct.pack_into("<I", data, 22, 10)
    struct.pack_into("<H", data, 26, 8)
    struct.pack_into("<H", data, 28, 0)
    data[30:38] = b"test.txt"
    return bytes(data)
