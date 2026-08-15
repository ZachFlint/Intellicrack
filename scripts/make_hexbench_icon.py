# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Generate the multi-resolution Hexbench application icon.

The artwork is the Hexbench hex-dump silhouette: an accent address gutter
beside rows of byte cells, drawn from the application's own design tokens in
``src/hexbench/static/app.css`` so the launcher matches the app it starts.

Small sizes are not downscales of the 256px master. Below 48px the byte-cell
grid turns to mush, so the drawing switches to progressively coarser variants:
a four-row two-column dump at full size, the same grid without the plate
outline at compact sizes, and three full-width bars beside the gutter at micro
sizes. Each ``.ico`` entry is rendered natively at its own size.

Qt is a build-time dependency of this generator only. Hexbench itself stays
standard-library-only, which is why this module lives under ``scripts/``
rather than inside ``src/hexbench``.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
from typing import Final

from PyQt6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt
from PyQt6.QtGui import QBrush, QColor, QGuiApplication, QImage, QLinearGradient, QPainter, QPen


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
_DEFAULT_OUTPUT: Final[Path] = _REPO_ROOT / "src" / "hexbench" / "hexbench.ico"

_SURFACE_TOP: Final[str] = "#12151b"
_SURFACE_BOTTOM: Final[str] = "#0a0c10"
_SURFACE_MICRO_TOP: Final[str] = "#232a35"
_SURFACE_MICRO_BOTTOM: Final[str] = "#171b22"
_BORDER: Final[str] = "#3a4453"
_ACCENT: Final[str] = "#4c9df0"
_TEXT_PRIMARY: Final[str] = "#dfe4ec"
_TEXT_FAINT: Final[str] = "#7a8695"

_CANVAS: Final[float] = 256.0
_PLATE_RADIUS: Final[float] = 52.0

ICON_SIZES: Final[tuple[int, ...]] = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)
PNG_SIZES: Final[frozenset[int]] = frozenset({256})

_COMPACT_BELOW: Final[int] = 48
_MICRO_BELOW: Final[int] = 28

_ICONDIR = struct.Struct("<HHH")
_ICONDIRENTRY = struct.Struct("<BBBBHHII")
_BITMAPINFOHEADER = struct.Struct("<IiiHHIIiiII")
_ICONDIR_SIZE: Final[int] = 6
_ICONDIRENTRY_SIZE: Final[int] = 16
_DIB_HEADER_SIZE: Final[int] = 40
_MAX_DIRECTORY_DIMENSION: Final[int] = 256


def _plate(
    painter: QPainter,
    radius: float,
    *,
    outlined: bool,
    top: str = _SURFACE_TOP,
    bottom: str = _SURFACE_BOTTOM,
) -> None:
    """Paint the rounded background plate.

    Args:
        painter: Painter already scaled to the 256-unit design canvas.
        radius: Corner radius in design units.
        outlined: Whether to stroke the plate border. The hairline disappears
            into a smudge at micro sizes, so callers drop it there.
        top: Gradient start colour.
        bottom: Gradient end colour.
    """
    gradient = QLinearGradient(QPointF(0.0, 0.0), QPointF(0.0, _CANVAS))
    gradient.setColorAt(0.0, QColor(top))
    gradient.setColorAt(1.0, QColor(bottom))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QBrush(gradient))
    painter.drawRoundedRect(QRectF(0.0, 0.0, _CANVAS, _CANVAS), radius, radius)

    if outlined:
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor(_BORDER), 5.0))
        painter.drawRoundedRect(QRectF(2.5, 2.5, _CANVAS - 5.0, _CANVAS - 5.0), radius - 2.0, radius - 2.0)


def _draw_full(painter: QPainter) -> None:
    """Draw the full-detail dump: gutter plus four rows of two byte cells.

    Args:
        painter: Painter already scaled to the design canvas.
    """
    _plate(painter, _PLATE_RADIUS, outlined=True)
    painter.setPen(Qt.PenStyle.NoPen)

    painter.setBrush(QColor(_ACCENT))
    painter.drawRoundedRect(QRectF(44.0, 62.0, 34.0, 132.0), 10.0, 10.0)

    rows = (QColor(_TEXT_FAINT), QColor(_TEXT_PRIMARY), QColor(_ACCENT), QColor(_TEXT_FAINT))
    for index, color in enumerate(rows):
        top = 62.0 + index * 36.0
        painter.setBrush(color)
        painter.drawRoundedRect(QRectF(96.0, top, 54.0, 22.0), 7.0, 7.0)
        painter.drawRoundedRect(QRectF(160.0, top, 54.0, 22.0), 7.0, 7.0)


def _draw_compact(painter: QPainter) -> None:
    """Draw the compact dump: same grid, heavier strokes, no plate outline.

    Args:
        painter: Painter already scaled to the design canvas.
    """
    _plate(painter, 44.0, outlined=False)
    painter.setPen(Qt.PenStyle.NoPen)

    painter.setBrush(QColor(_ACCENT))
    painter.drawRoundedRect(QRectF(38.0, 56.0, 40.0, 144.0), 12.0, 12.0)

    rows = (QColor(_TEXT_FAINT), QColor(_TEXT_PRIMARY), QColor(_ACCENT), QColor(_TEXT_FAINT))
    for index, color in enumerate(rows):
        top = 56.0 + index * 40.0
        painter.setBrush(color)
        painter.drawRoundedRect(QRectF(96.0, top, 60.0, 28.0), 8.0, 8.0)
        painter.drawRoundedRect(QRectF(166.0, top, 52.0, 28.0), 8.0, 8.0)


def _draw_micro(painter: QPainter) -> None:
    """Draw the micro variant: gutter plus three full-width bars.

    At 16-24px the two-column split collapses into noise, so the byte cells
    merge into single bars that still read as a dump beside an address gutter.

    Args:
        painter: Painter already scaled to the design canvas.
    """
    _plate(painter, 40.0, outlined=False, top=_SURFACE_MICRO_TOP, bottom=_SURFACE_MICRO_BOTTOM)
    painter.setPen(Qt.PenStyle.NoPen)

    painter.setBrush(QColor(_ACCENT))
    painter.drawRoundedRect(QRectF(40.0, 56.0, 44.0, 144.0), 10.0, 10.0)

    rows = (QColor(_TEXT_FAINT), QColor(_TEXT_PRIMARY), QColor(_ACCENT))
    for index, color in enumerate(rows):
        top = 56.0 + index * 54.0
        painter.setBrush(color)
        painter.drawRoundedRect(QRectF(104.0, top, 112.0, 36.0), 10.0, 10.0)


def render_icon(size: int) -> QImage:
    """Render the icon natively at one pixel size.

    Args:
        size: Edge length in pixels.

    Returns:
        QImage: A premultiplied ARGB32 image of ``size`` by ``size`` pixels.
    """
    image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, on=True)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, on=True)
    painter.scale(size / _CANVAS, size / _CANVAS)
    if size < _MICRO_BELOW:
        _draw_micro(painter)
    elif size < _COMPACT_BELOW:
        _draw_compact(painter)
    else:
        _draw_full(painter)
    painter.end()
    return image


def _png_bytes(image: QImage) -> bytes:
    """Encode an image as PNG.

    Args:
        image: Image to encode.

    Returns:
        bytes: The PNG file contents.

    Raises:
        RuntimeError: If Qt fails to encode the image.
    """
    payload = QByteArray()
    buffer = QBuffer(payload)
    if not buffer.open(QIODevice.OpenModeFlag.WriteOnly):
        msg = "could not open an in-memory buffer for PNG encoding"
        raise RuntimeError(msg)
    ok = image.save(buffer, "PNG")
    buffer.close()
    if not ok:
        msg = f"Qt failed to encode a {image.width()}x{image.height()} PNG"
        raise RuntimeError(msg)
    return payload.data()


def _dib_bytes(image: QImage) -> bytes:
    """Encode an image as a bottom-up 32-bit DIB with an empty AND mask.

    Windows expects classic icon entries to carry a ``BITMAPINFOHEADER`` whose
    height is doubled to cover the colour bitmap plus a 1-bit transparency
    mask. The alpha channel already carries transparency, so the mask is
    written as all-zero (fully opaque) and padded to the required 4-byte row
    stride.

    Args:
        image: Image to encode.

    Returns:
        bytes: The DIB payload for one ``ICONDIRENTRY``.
    """
    converted = image.convertToFormat(QImage.Format.Format_ARGB32)
    width = converted.width()
    height = converted.height()

    pixels = bytearray()
    for y in range(height - 1, -1, -1):
        for x in range(width):
            argb = converted.pixel(x, y)
            alpha = (argb >> 24) & 0xFF
            red = (argb >> 16) & 0xFF
            green = (argb >> 8) & 0xFF
            blue = argb & 0xFF
            pixels += bytes((blue, green, red, alpha))

    mask_stride = ((width + 31) // 32) * 4
    mask = bytes(mask_stride * height)

    header = _BITMAPINFOHEADER.pack(
        _DIB_HEADER_SIZE,
        width,
        height * 2,
        1,
        32,
        0,
        len(pixels) + len(mask),
        0,
        0,
        0,
        0,
    )
    return header + bytes(pixels) + mask


def build_ico(sizes: tuple[int, ...] = ICON_SIZES) -> bytes:
    """Build a complete multi-resolution ICO file.

    Entries at ``PNG_SIZES`` are stored PNG-compressed, which is how Windows
    Vista and later carry the 256px entry; every other entry is a classic DIB
    so older shell paths render it too.

    Args:
        sizes: Edge lengths to include, ascending.

    Returns:
        bytes: The complete ``.ico`` file contents.
    """
    payloads: list[tuple[int, bytes]] = []
    for size in sizes:
        image = render_icon(size)
        payloads.append((size, _png_bytes(image) if size in PNG_SIZES else _dib_bytes(image)))

    offset = _ICONDIR_SIZE + _ICONDIRENTRY_SIZE * len(payloads)
    directory = bytearray(_ICONDIR.pack(0, 1, len(payloads)))
    body = bytearray()
    for size, data in payloads:
        dimension = 0 if size >= _MAX_DIRECTORY_DIMENSION else size
        directory += _ICONDIRENTRY.pack(dimension, dimension, 0, 0, 1, 32, len(data), offset)
        body += data
        offset += len(data)
    return bytes(directory) + bytes(body)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: write the Hexbench icon to disk.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``).

    Returns:
        int: Process exit code.
    """
    parser = argparse.ArgumentParser(description="Generate the Hexbench application icon.")
    _ = parser.add_argument(
        "--output",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help=f"Destination .ico path (default: {_DEFAULT_OUTPUT}).",
    )
    args = parser.parse_args(argv)
    output: Path = args.output

    _app = QGuiApplication(sys.argv[:1])
    data = build_ico()
    output.parent.mkdir(parents=True, exist_ok=True)
    _ = output.write_bytes(data)
    print(f"==> {output} ({len(data)} bytes, {len(ICON_SIZES)} sizes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
