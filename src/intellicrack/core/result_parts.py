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
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from intellicrack.core.types import (
    EmbeddedResourcePart,
    ImageResultPart,
    StructuredResultPart,
    TextResultPart,
    ToolResultPart,
)
from intellicrack.core.untrusted_text import UNTRUSTED_BLOCK_END, UNTRUSTED_BLOCK_START


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


IMAGE_MIME_PNG: Final[str] = "image/png"
IMAGE_MIME_JPEG: Final[str] = "image/jpeg"
IMAGE_MIME_GIF: Final[str] = "image/gif"
IMAGE_MIME_WEBP: Final[str] = "image/webp"
IMAGE_MIME_BMP: Final[str] = "image/bmp"
IMAGE_MIME_TIFF: Final[str] = "image/tiff"
IMAGE_MIME_HEIC: Final[str] = "image/heic"
IMAGE_MIME_HEIF: Final[str] = "image/heif"
IMAGE_MIME_AVIF: Final[str] = "image/avif"

_MIME_ALIASES: Final[dict[str, str]] = {"image/jpg": IMAGE_MIME_JPEG, "image/pjpeg": IMAGE_MIME_JPEG, "image/x-png": IMAGE_MIME_PNG}

_ISO_BMFF_BRANDS: Final[dict[bytes, str]] = {
    b"heic": IMAGE_MIME_HEIC,
    b"heix": IMAGE_MIME_HEIC,
    b"hevc": IMAGE_MIME_HEIC,
    b"heim": IMAGE_MIME_HEIC,
    b"heis": IMAGE_MIME_HEIC,
    b"mif1": IMAGE_MIME_HEIF,
    b"msf1": IMAGE_MIME_HEIF,
    b"avif": IMAGE_MIME_AVIF,
    b"avis": IMAGE_MIME_AVIF,
}

_RIFF_HEADER_LEN: Final[int] = 12
_ISO_BMFF_HEADER_LEN: Final[int] = 12


def normalize_image_mime(mime_type: str) -> str:
    """Bring a declared image media type to its canonical spelling.

    Args:
        mime_type: The media type a tool declared.

    Returns:
        str: The lower-cased type without parameters, with common aliases
        such as ``image/jpg`` mapped to their registered name.
    """
    bare = mime_type.split(";", maxsplit=1)[0].strip().lower()
    return _MIME_ALIASES.get(bare, bare)


def sniff_image_mime(header: bytes) -> str | None:
    """Identify an image format from its leading bytes.

    Args:
        header: The decoded image's leading bytes.

    Returns:
        str | None: The media type the signature belongs to, or ``None`` when
        no known signature matches.
    """
    if header.startswith(_PNG_SIGNATURE):
        return IMAGE_MIME_PNG
    if header.startswith(_JPEG_SOI):
        return IMAGE_MIME_JPEG
    if header[:6] in _GIF_SIGNATURES:
        return IMAGE_MIME_GIF
    if len(header) >= _RIFF_HEADER_LEN and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return IMAGE_MIME_WEBP
    if header.startswith(b"BM"):
        return IMAGE_MIME_BMP
    if header[:4] in {b"II*\x00", b"MM\x00*"}:
        return IMAGE_MIME_TIFF
    if len(header) >= _ISO_BMFF_HEADER_LEN and header[4:8] == b"ftyp":
        return _ISO_BMFF_BRANDS.get(header[8:12])
    return None


@dataclass(frozen=True, slots=True)
class ImageInspection:
    """What an image payload turned out to be.

    Attributes:
        data: The base64 payload with any whitespace removed, which is the
            form every provider accepts.
        mime_type: The media type to send it as: the one its bytes prove
            when they carry a known signature, else the declared one.
        byte_count: Size of the decoded image.
        dimensions: Width and height in pixels, when the header gives them.
        problem: Why the payload is not a usable image, or ``None`` when it
            is one.
    """

    data: str
    mime_type: str
    byte_count: int
    dimensions: tuple[int, int] | None
    problem: str | None


def inspect_image(data: str, declared_mime: str) -> ImageInspection:
    """Check that a payload is the image it claims to be.

    The whole payload is decoded, strictly: a stray character anywhere makes
    it invalid, because a provider that receives it rejects the request and
    every later request that replays it. A payload whose bytes carry a known
    image signature is sent under the type the bytes prove, whatever was
    declared, so a server that mislabels a JPEG as PNG does not poison the
    conversation.

    Args:
        data: The base64-encoded image.
        declared_mime: The media type the tool declared.

    Returns:
        ImageInspection: The verdict and the normalized payload.
    """
    declared = normalize_image_mime(declared_mime)
    compact = "".join(data.split())
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return ImageInspection(compact, declared, 0, None, "the payload is not valid base64")
    if not decoded:
        return ImageInspection(compact, declared, 0, None, "the payload is empty")
    sniffed = sniff_image_mime(decoded[:_HEADER_BYTES])
    dimensions = image_dimensions(compact)
    if sniffed is not None:
        return ImageInspection(compact, sniffed, len(decoded), dimensions, None)
    if not declared.startswith("image/"):
        return ImageInspection(compact, declared, len(decoded), None, f"the declared type {declared!r} is not an image type")
    if declared in {IMAGE_MIME_PNG, IMAGE_MIME_JPEG, IMAGE_MIME_GIF, IMAGE_MIME_WEBP}:
        return ImageInspection(compact, declared, len(decoded), None, f"the bytes are not a {declared} image")
    return ImageInspection(compact, declared, len(decoded), dimensions, None)


@dataclass(frozen=True, slots=True)
class ImagePolicy:
    """Which images one endpoint accepts.

    Attributes:
        mime_types: The media types it accepts.
        max_edge: Longest image edge in pixels it accepts, or ``None``.
        max_bytes: Largest decoded image it accepts, or ``None``.
    """

    mime_types: frozenset[str]
    max_edge: int | None = None
    max_bytes: int | None = None

    def refusal(self, part: ImageResultPart) -> str | None:
        """Say why this endpoint would reject an image, if it would.

        Args:
            part: The image.

        Returns:
            str | None: The reason, or ``None`` when the image can be sent.
        """
        inspection = inspect_image(part.data, part.mime_type)
        if inspection.problem is not None:
            return inspection.problem
        if inspection.mime_type not in self.mime_types:
            accepted = ", ".join(sorted(self.mime_types))
            return f"this endpoint accepts only {accepted}"
        if self.max_bytes is not None and inspection.byte_count > self.max_bytes:
            return f"it is {inspection.byte_count} bytes, over this endpoint's {self.max_bytes}-byte limit"
        dimensions = inspection.dimensions
        if self.max_edge is not None and dimensions is not None and max(dimensions) > self.max_edge:
            return f"it is {dimensions[0]}x{dimensions[1]} pixels, over this endpoint's {self.max_edge}-pixel edge limit"
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
        truncated = _truncate_keeping_fence(text, max(remaining, 0), fence=isinstance(part, StructuredResultPart))
        remaining = 0
        if isinstance(part, EmbeddedResourcePart):
            bounded.append(EmbeddedResourcePart(uri=part.uri, text=truncated, data=part.data, mime_type=part.mime_type))
        else:
            bounded.append(TextResultPart(text=truncated))
    return bounded


def _truncate_keeping_fence(text: str, keep: int, *, fence: bool) -> str:
    """Cut text to a budget without leaving an untrusted block unclosed.

    Text already wrapped in the untrusted-text fence is cut inside the fence
    and closed again; a structured part, whose JSON is the server's own data,
    is fenced as it is cut.

    Args:
        text: The text to cut.
        keep: How many characters of content to keep.
        fence: Whether to fence text that is not fenced yet.

    Returns:
        str: The truncated text, with a note saying how much was dropped.
    """
    opening = f"{UNTRUSTED_BLOCK_START}\n"
    closing = f"\n{UNTRUSTED_BLOCK_END}"
    fenced = text.startswith(opening) and text.endswith(closing)
    body = text[len(opening) : len(text) - len(closing)] if fenced else text
    kept = body[:keep]
    truncated = f"{kept}{_TRUNCATION_NOTE.format(omitted=len(body) - len(kept))}"
    return f"{opening}{truncated}{closing}" if fenced or fence else truncated


__all__ = [
    "IMAGE_MAX_LONG_EDGE",
    "IMAGE_MAX_TOKENS",
    "IMAGE_MIME_AVIF",
    "IMAGE_MIME_BMP",
    "IMAGE_MIME_GIF",
    "IMAGE_MIME_HEIC",
    "IMAGE_MIME_HEIF",
    "IMAGE_MIME_JPEG",
    "IMAGE_MIME_PNG",
    "IMAGE_MIME_TIFF",
    "IMAGE_MIME_WEBP",
    "IMAGE_PATCH_PIXELS",
    "ImageInspection",
    "ImagePolicy",
    "bound_result_parts",
    "estimate_image_tokens",
    "image_dimensions",
    "inspect_image",
    "normalize_image_mime",
    "sniff_image_mime",
]
