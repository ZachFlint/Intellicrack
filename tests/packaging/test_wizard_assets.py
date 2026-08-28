# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for the installer's theme-aware wizard imagery.

The Inno Setup ``.iss`` advertises a theme-aware wizard: ``WizardImageFile`` is
the light banner and ``WizardImageFileDynamicDark`` the dark one, and Setup
swaps between them with the system theme. For that claim to be true the two
banners must be genuinely different images with the light one visibly lighter --
not the same dark composite shipped twice. The small wizard image must also use
Inno's small-image aspect (55x58 base, 165x174 at 3x) so it reads as a logo
rather than a clipped square.

These gates decode the real PNGs with the standard library (no Pillow
dependency, matching :mod:`tests.ui.test_app_icon_frames`) and assert:

* the light and dark banners are not byte-identical and share one canvas size;
* the light banner's mean luma is well above the dark banner's, and lands on the
  light side of mid-grey while the dark banner lands on the dark side;
* the small wizard image is exactly 165x174.

Reverting to a single-dark render (the original bug) collapses the luma gap and
makes the banners byte-identical, turning these red. The banner and small PNGs
live under ``packaging/wizard`` (mounted in the sandbox); the icon frame set is
gated separately by :mod:`tests.ui.test_app_icon_frames`.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Final


_PNG_SIGNATURE: Final[bytes] = b"\x89PNG\r\n\x1a\n"
_WIZARD_DIR: Final[Path] = Path(__file__).resolve().parents[2] / "packaging" / "wizard"
_BANNER_LIGHT: Final[Path] = _WIZARD_DIR / "banner-light.png"
_BANNER_DARK: Final[Path] = _WIZARD_DIR / "banner-dark.png"
_SMALL: Final[Path] = _WIZARD_DIR / "small.png"

# Channel byte counts for the truecolour PNG colour types System.Drawing emits.
_BYTES_PER_PIXEL: Final[dict[int, int]] = {2: 3, 6: 4}
_EXPECTED_BIT_DEPTH: Final[int] = 8
_MID_GREY: Final[float] = 128.0
_EXPECTED_SMALL_SIZE: Final[tuple[int, int]] = (165, 174)

# Luminance coefficients (Rec. 601).
_LUMA_R: Final[float] = 0.299
_LUMA_G: Final[float] = 0.587
_LUMA_B: Final[float] = 0.114


def _paeth(a: int, b: int, c: int) -> int:
    """Apply the PNG Paeth predictor to three neighbouring reconstructed bytes.

    Args:
        a: The byte to the left.
        b: The byte above.
        c: The byte above-left.

    Returns:
        int: The predicted base value (whichever neighbour the predictor selects).
    """
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _read_ihdr_and_idat(data: bytes) -> tuple[int, int, int, int, bytes]:
    """Parse a PNG's header and concatenated image data.

    Args:
        data: The full byte content of a PNG file.

    Returns:
        tuple[int, int, int, int, bytes]: ``(width, height, bit_depth,
            colour_type, idat)`` -- the IHDR fields and the concatenated raw
            (still zlib-compressed) IDAT payload.

    Raises:
        ValueError: If the data is not a PNG or carries no IHDR/IDAT.
    """
    if not data.startswith(_PNG_SIGNATURE):
        msg = "not a PNG (missing signature)"
        raise ValueError(msg)
    pos = len(_PNG_SIGNATURE)
    width = height = bit_depth = colour_type = -1
    idat = bytearray()
    while pos + 8 <= len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        chunk_type = data[pos + 4 : pos + 8]
        payload = data[pos + 8 : pos + 8 + length]
        if chunk_type == b"IHDR":
            width, height, bit_depth, colour_type = struct.unpack_from(">IIBB", payload, 0)
        elif chunk_type == b"IDAT":
            idat.extend(payload)
        elif chunk_type == b"IEND":
            break
        pos += 12 + length
    if width < 0 or not idat:
        msg = "PNG is missing its IHDR or IDAT chunks"
        raise ValueError(msg)
    return width, height, bit_depth, colour_type, bytes(idat)


def _defilter_scanline(line: bytearray, prior: bytearray, bpp: int, filter_type: int) -> None:
    """Reconstruct one PNG scanline in place using its filter and the prior row.

    Args:
        line: The filtered scanline bytes; reconstructed in place.
        prior: The already-reconstructed previous scanline (zeros for the first).
        bpp: Bytes per pixel (the filter's left-neighbour distance).
        filter_type: The PNG filter byte (0 None, 1 Sub, 2 Up, 3 Average, 4 Paeth).
    """
    for index in range(len(line)):
        left = line[index - bpp] if index >= bpp else 0
        up = prior[index]
        up_left = prior[index - bpp] if index >= bpp else 0
        if filter_type == 1:
            line[index] = (line[index] + left) & 0xFF
        elif filter_type == 2:
            line[index] = (line[index] + up) & 0xFF
        elif filter_type == 3:
            line[index] = (line[index] + ((left + up) >> 1)) & 0xFF
        elif filter_type == 4:
            line[index] = (line[index] + _paeth(left, up, up_left)) & 0xFF


def _decode_rgb(data: bytes) -> tuple[int, int, bytearray, int]:
    """Decode an 8-bit truecolour PNG into reconstructed pixel bytes.

    Only the 8-bit RGB/RGBA colour types produced by ``System.Drawing`` are
    supported; anything else is rejected loudly rather than mis-decoded.

    Args:
        data: The full byte content of a PNG file.

    Returns:
        tuple[int, int, bytearray, int]: ``(width, height, pixels,
            bytes_per_pixel)`` where ``pixels`` holds the defiltered image rows.

    Raises:
        ValueError: If the PNG is not an 8-bit RGB/RGBA image.
    """
    width, height, bit_depth, colour_type, idat = _read_ihdr_and_idat(data)
    if bit_depth != _EXPECTED_BIT_DEPTH or colour_type not in _BYTES_PER_PIXEL:
        msg = f"unsupported PNG (bit_depth={bit_depth}, colour_type={colour_type}); expected 8-bit RGB/RGBA"
        raise ValueError(msg)
    bpp = _BYTES_PER_PIXEL[colour_type]
    raw = zlib.decompress(idat)
    stride = width * bpp
    pixels = bytearray()
    prior = bytearray(stride)
    offset = 0
    for _row in range(height):
        filter_type = raw[offset]
        line = bytearray(raw[offset + 1 : offset + 1 + stride])
        offset += 1 + stride
        _defilter_scanline(line, prior, bpp, filter_type)
        pixels.extend(line)
        prior = line
    return width, height, pixels, bpp


def png_dimensions(path: Path) -> tuple[int, int]:
    """Return the ``(width, height)`` of a PNG from its IHDR.

    Args:
        path: The PNG file to inspect.

    Returns:
        tuple[int, int]: The image dimensions in pixels.
    """
    width, height, _bit_depth, _colour_type, _idat = _read_ihdr_and_idat(path.read_bytes())
    return width, height


def mean_luma(path: Path) -> float:
    """Compute the mean Rec. 601 luma of an 8-bit truecolour PNG.

    Args:
        path: The PNG file to inspect.

    Returns:
        float: The mean luminance across all pixels, in ``[0, 255]``.
    """
    width, height, pixels, bpp = _decode_rgb(path.read_bytes())
    total = 0.0
    count = width * height
    for pixel in range(count):
        base = pixel * bpp
        total += _LUMA_R * pixels[base] + _LUMA_G * pixels[base + 1] + _LUMA_B * pixels[base + 2]
    return total / count


def test_light_and_dark_banners_are_distinct_and_correctly_toned() -> None:
    """Real gate: the two banners are distinct and the light one is genuinely lighter.

    The theme-aware wizard needs two real banners. This asserts they are not the
    same bytes, share one canvas size, and that the light banner's mean luma sits
    on the light side of mid-grey well above the dark banner's, which sits on the
    dark side -- exactly what a single-dark render (the original bug) violates.
    """
    assert _BANNER_LIGHT.is_file(), f"light banner missing: {_BANNER_LIGHT}"
    assert _BANNER_DARK.is_file(), f"dark banner missing: {_BANNER_DARK}"

    assert _BANNER_LIGHT.read_bytes() != _BANNER_DARK.read_bytes(), (
        "banner-light.png and banner-dark.png are byte-identical: the theme-aware wizard ships one image twice"
    )
    assert png_dimensions(_BANNER_LIGHT) == png_dimensions(_BANNER_DARK), (
        "the light and dark banners must share one canvas size to swap cleanly with the theme"
    )

    light = mean_luma(_BANNER_LIGHT)
    dark = mean_luma(_BANNER_DARK)
    assert light > dark + 50.0, f"light banner ({light:.1f}) is not clearly lighter than the dark banner ({dark:.1f})"
    assert light > _MID_GREY, f"the light banner mean luma ({light:.1f}) must land on the light side of mid-grey"
    assert dark < _MID_GREY, f"the dark banner mean luma ({dark:.1f}) must land on the dark side of mid-grey"


def test_small_wizard_image_uses_the_small_aspect() -> None:
    """Real gate: the small wizard image is 165x174 (Inno 55x58 base at 3x).

    A full-bleed square (the earlier bug) would not carry this logo aspect;
    pinning the exact dimensions catches a regression to the wrong ratio.
    """
    assert _SMALL.is_file(), f"small wizard image missing: {_SMALL}"
    assert png_dimensions(_SMALL) == _EXPECTED_SMALL_SIZE, (
        f"small.png must be {_EXPECTED_SMALL_SIZE} (55x58 at 3x), got {png_dimensions(_SMALL)}"
    )


def _encode_solid_rgb(width: int, height: int, colour: tuple[int, int, int]) -> bytes:
    """Encode a solid-colour 8-bit RGB PNG for the decoder falsifiability proof.

    Args:
        width: Image width in pixels.
        height: Image height in pixels.
        colour: The ``(r, g, b)`` fill colour.

    Returns:
        bytes: A complete PNG byte stream (signature, IHDR, IDAT, IEND).
    """
    raw = bytearray()
    row = bytes(colour) * width
    for _ in range(height):
        raw.append(0)
        raw.extend(row)
    compressed = zlib.compress(bytes(raw))

    def _chunk(tag: bytes, payload: bytes) -> bytes:
        body = tag + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return _PNG_SIGNATURE + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", compressed) + _chunk(b"IEND", b"")


def _mean_luma_bytes(png: bytes) -> float:
    """Compute the mean Rec. 601 luma of an in-memory 8-bit truecolour PNG.

    Args:
        png: A complete PNG byte stream.

    Returns:
        float: The mean luminance across all pixels, in ``[0, 255]``.
    """
    width, height, pixels, bpp = _decode_rgb(png)
    total = 0.0
    count = width * height
    for pixel in range(count):
        base = pixel * bpp
        total += _LUMA_R * pixels[base] + _LUMA_G * pixels[base + 1] + _LUMA_B * pixels[base + 2]
    return total / count


def test_luma_decoder_is_falsifiable() -> None:
    """The luma reader ranks a synthetic light image above a dark one.

    Proves the decode path genuinely reads pixel content: a near-white PNG must
    score far higher than a near-black one. A decoder that returned a constant
    (and so could not tell the banners apart) fails this.
    """
    light_luma = _mean_luma_bytes(_encode_solid_rgb(2, 2, (240, 240, 240)))
    dark_luma = _mean_luma_bytes(_encode_solid_rgb(2, 2, (10, 10, 10)))
    assert light_luma > 200.0
    assert dark_luma < 40.0
    assert light_luma > dark_luma
