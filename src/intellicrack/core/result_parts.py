# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Measuring and bounding multi-part tool results for the model's context.

A multi-part result mixes prose, structured JSON and binary media. Each costs
the context window differently: text is tokenized, but an image is billed by
its pixel dimensions, never by the length of its base64 encoding. These
helpers price each part the way a provider does and bound the textual parts
so one large result cannot crowd the rest of the conversation out.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import struct
from typing import TYPE_CHECKING, Final

from intellicrack.core.types import (
    EmbeddedResourcePart,
    ImageResultPart,
    StructuredResultPart,
    TextResultPart,
    ToolResultPart,
)


if TYPE_CHECKING:
    from collections.abc import Iterable


IMAGE_PATCH_PIXELS: Final[int] = 28
"""Edge of one visual-token patch on the most expensive supported vision model."""

IMAGE_MAX_LONG_EDGE: Final[int] = 2576
"""Longest edge a vision model processes before downscaling an image."""

IMAGE_MAX_TOKENS: Final[int] = 4784
"""Most visual tokens one image can cost after downscaling."""

_HEADER_BYTES: Final[int] = 64 * 1024
"""How much of an image is decoded to find its dimensions."""

_TRUNCATION_NOTE: Final[str] = "\n... [truncated {omitted} characters; request a narrower range for full detail]"

_PNG_HEADER_LEN: Final[int] = 24
_GIF_HEADER_LEN: Final[int] = 10
_WEBP_HEADER_LEN: Final[int] = 30
_JPEG_MARKER_PREFIX: Final[int] = 0xFF
_PNG_SIGNATURE: Final[bytes] = b"\x89PNG\r\n\x1a\n"
_GIF_SIGNATURES: Final[tuple[bytes, ...]] = (b"GIF87a", b"GIF89a")
_JPEG_SOI: Final[bytes] = b"\xff\xd8"
_JPEG_SOF_MARKERS: Final[frozenset[int]] = frozenset({0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF})
_JPEG_STANDALONE_MARKERS: Final[frozenset[int]] = frozenset({0x01, *range(0xD0, 0xD9)})


def _decode_header(data: str) -> bytes:
    """Decode just enough of a base64 payload to read an image header.

    Args:
        data: The base64-encoded image.

    Returns:
        bytes: The leading decoded bytes, or empty bytes when the payload is
        not valid base64.
    """
    prefix = "".join(data[: (_HEADER_BYTES // 3) * 4].split())
    prefix = prefix[: len(prefix) - len(prefix) % 4]
    try:
        return base64.b64decode(prefix, validate=True)
    except (binascii.Error, ValueError):
        return b""


def _png_dimensions(header: bytes) -> tuple[int, int] | None:
    """Read the dimensions from a PNG ``IHDR`` chunk.

    Args:
        header: The image's leading bytes.

    Returns:
        tuple[int, int] | None: Width and height, or ``None`` when absent.
    """
    if len(header) < _PNG_HEADER_LEN or not header.startswith(_PNG_SIGNATURE) or header[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", header[16:24])
    return int(width), int(height)


def _gif_dimensions(header: bytes) -> tuple[int, int] | None:
    """Read the dimensions from a GIF logical screen descriptor.

    Args:
        header: The image's leading bytes.

    Returns:
        tuple[int, int] | None: Width and height, or ``None`` when absent.
    """
    if len(header) < _GIF_HEADER_LEN or header[:6] not in _GIF_SIGNATURES:
        return None
    width, height = struct.unpack("<HH", header[6:10])
    return int(width), int(height)


def _webp_dimensions(header: bytes) -> tuple[int, int] | None:
    """Read the dimensions from a WebP ``VP8``, ``VP8L`` or ``VP8X`` chunk.

    Args:
        header: The image's leading bytes.

    Returns:
        tuple[int, int] | None: Width and height, or ``None`` when absent.
    """
    if len(header) < _WEBP_HEADER_LEN or header[:4] != b"RIFF" or header[8:12] != b"WEBP":
        return None
    chunk = header[12:16]
    if chunk == b"VP8X":
        width = int.from_bytes(header[24:27], "little") + 1
        height = int.from_bytes(header[27:30], "little") + 1
        return width, height
    if chunk == b"VP8L":
        bits = int.from_bytes(header[21:25], "little")
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    if chunk == b"VP8 ":
        width, height = struct.unpack("<HH", header[26:30])
        return int(width) & 0x3FFF, int(height) & 0x3FFF
    return None


def _jpeg_dimensions(header: bytes) -> tuple[int, int] | None:
    """Walk JPEG segments to the first start-of-frame marker.

    Args:
        header: The image's leading bytes.

    Returns:
        tuple[int, int] | None: Width and height, or ``None`` when no frame
        header lies within ``header``.
    """
    if not header.startswith(_JPEG_SOI):
        return None
    offset = 2
    while offset + 4 <= len(header):
        if header[offset] != _JPEG_MARKER_PREFIX:
            return None
        marker = header[offset + 1]
        if marker == _JPEG_MARKER_PREFIX:
            offset += 1
            continue
        if marker in _JPEG_STANDALONE_MARKERS:
            offset += 2
            continue
        (length,) = struct.unpack(">H", header[offset + 2 : offset + 4])
        if marker in _JPEG_SOF_MARKERS:
            if offset + 9 > len(header):
                return None
            height, width = struct.unpack(">HH", header[offset + 5 : offset + 9])
            return int(width), int(height)
        offset += 2 + int(length)
    return None


def image_dimensions(data: str) -> tuple[int, int] | None:
    """Read an image's pixel dimensions from its base64 encoding.

    Only the header is decoded. PNG, JPEG, GIF and WebP are recognised,
    which covers every format the supported vision APIs accept.

    Args:
        data: The base64-encoded image.

    Returns:
        tuple[int, int] | None: Width and height in pixels, or ``None`` when
        the format is not recognised or the header is malformed.
    """
    header = _decode_header(data)
    for reader in (_png_dimensions, _jpeg_dimensions, _gif_dimensions, _webp_dimensions):
        dimensions = reader(header)
        if dimensions is not None and dimensions[0] > 0 and dimensions[1] > 0:
            return dimensions
    return None


def estimate_image_tokens(part: ImageResultPart) -> int:
    """Estimate how much of the context window one image occupies.

    Vision models bill an image by its pixel area, not by the size of its
    encoding. The estimate follows the costliest published rule among the
    supported providers: one visual token per 28x28 patch, after the image
    is scaled down to fit a 2576-pixel long edge and a 4784-token ceiling.
    That bound is at or above the tile-based cost other providers publish, so
    history trimmed against it never overflows. An image whose dimensions
    cannot be read is charged the ceiling.

    Args:
        part: The image part to price.

    Returns:
        int: Estimated visual tokens.
    """
    dimensions = image_dimensions(part.data)
    if dimensions is None:
        return IMAGE_MAX_TOKENS
    width, height = dimensions
    scale = min(1.0, IMAGE_MAX_LONG_EDGE / max(width, height))
    patches = math.ceil(width * scale / IMAGE_PATCH_PIXELS) * math.ceil(height * scale / IMAGE_PATCH_PIXELS)
    if patches > IMAGE_MAX_TOKENS:
        area_scale = math.sqrt(IMAGE_MAX_TOKENS / patches)
        patches = math.ceil(width * scale * area_scale / IMAGE_PATCH_PIXELS) * math.ceil(height * scale * area_scale / IMAGE_PATCH_PIXELS)
    return min(patches, IMAGE_MAX_TOKENS)


def _part_text(part: ToolResultPart) -> str | None:
    """Return the text a textual part contributes, or ``None`` for media.

    Args:
        part: The part to inspect.

    Returns:
        str | None: The part's text, its JSON encoding for a structured part,
        or ``None`` for a part that carries no text.
    """
    if isinstance(part, TextResultPart):
        return part.text
    if isinstance(part, EmbeddedResourcePart):
        return part.text
    if isinstance(part, StructuredResultPart):
        return json.dumps(part.content, sort_keys=True)
    return None


def bound_result_parts(parts: Iterable[ToolResultPart], max_chars: int) -> list[ToolResultPart]:
    """Bound the textual parts of a result to one shared character budget.

    Text, inlined resource text and structured JSON draw on the budget in
    order. The part that crosses it is cut to what remains, with a marker
    saying how much was dropped, and a structured part that no longer fits
    is replaced by its truncated JSON text rather than by broken JSON.
    Media and resource references pass through untouched: truncating base64
    corrupts it rather than shrinking it, and what an image costs is set by
    its pixel dimensions.

    Args:
        parts: The result parts, in order.
        max_chars: The shared character budget for every textual part.

    Returns:
        list[ToolResultPart]: The bounded parts. Parts are returned
        unchanged, and in the same order, when everything fits.
    """
    remaining = max_chars
    bounded: list[ToolResultPart] = []
    for part in parts:
        text = _part_text(part)
        if text is None:
            bounded.append(part)
            continue
        if len(text) <= remaining:
            remaining -= len(text)
            bounded.append(part)
            continue
        kept = text[: max(remaining, 0)]
        truncated = f"{kept}{_TRUNCATION_NOTE.format(omitted=len(text) - len(kept))}"
        remaining = 0
        if isinstance(part, EmbeddedResourcePart):
            bounded.append(EmbeddedResourcePart(uri=part.uri, text=truncated, data=part.data, mime_type=part.mime_type))
        else:
            bounded.append(TextResultPart(text=truncated))
    return bounded


__all__ = [
    "IMAGE_MAX_LONG_EDGE",
    "IMAGE_MAX_TOKENS",
    "IMAGE_PATCH_PIXELS",
    "bound_result_parts",
    "estimate_image_tokens",
    "image_dimensions",
]
