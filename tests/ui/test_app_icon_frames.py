# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Structural gates for the bundled application icon (``icon.ico``).

The app icon is the single source of the Intellicrack wordmark: the installer's
``SetupIconFile``, the app/window icon, and the wizard banners are all derived
from it. These tests assert the icon stays a crisp multi-frame ICO (the full
title-bar-through-master frame set, PNG-compressed for Windows 10+, with a 256px
master that decodes to a true 256x256), and that the rebranded AdobeInjector
tool icon remains byte-identical to it so the brand does not drift out of sync
across the project.

Parsing is done from raw bytes with the standard library (no Pillow dependency)
so the gate runs anywhere the repository is checked out.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from intellicrack.ui.resources.resource_helper import get_assets_path


if TYPE_CHECKING:
    from pathlib import Path


_PNG_SIGNATURE: bytes = b"\x89PNG\r\n\x1a\n"
_EXPECTED_FRAME_SIZES: frozenset[int] = frozenset({16, 20, 24, 32, 40, 48, 64, 128, 256})
_MASTER_FRAME_SIZE: int = 256


def _app_icon_path() -> Path:
    """Return the path to the bundled application icon.

    Returns:
        Path: Absolute path to ``src/intellicrack/assets/icon.ico``.
    """
    return get_assets_path() / "icon.ico"


def _rebranded_tool_icon_path() -> Path:
    """Return the path to the rebranded AdobeInjector tool icon.

    Returns:
        Path: Absolute path to the tool's ``Intellicrack.ico`` brand copy.
    """
    repo_root = get_assets_path().parents[2]
    return repo_root / "tools" / "AdobeInjector" / "Source" / "Rebranded" / "Intellicrack.ico"


def _parse_ico_frames(data: bytes) -> list[tuple[int, int, int]]:
    """Parse an ICO's directory into per-frame (width, byte-size, byte-offset).

    Args:
        data: The full byte content of an ``.ico`` file.

    Returns:
        list[tuple[int, int, int]]: One ``(width, size, offset)`` tuple per
        frame, with a declared width of 0 normalised to 256 per the ICO spec.

    Raises:
        ValueError: If the ICONDIR header is not a valid icon directory.
    """
    reserved, image_type, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or image_type != 1 or count == 0:
        msg = f"not a valid ICO directory (reserved={reserved}, type={image_type}, count={count})"
        raise ValueError(msg)
    frames: list[tuple[int, int, int]] = []
    for index in range(count):
        entry = 6 + index * 16
        width = data[entry]
        normalised_width = 256 if width == 0 else width
        size = struct.unpack_from("<I", data, entry + 8)[0]
        offset = struct.unpack_from("<I", data, entry + 12)[0]
        frames.append((normalised_width, size, offset))
    return frames


def _png_dimensions(data: bytes) -> tuple[int, int]:
    """Extract the pixel dimensions from a PNG byte stream's IHDR chunk.

    Args:
        data: Bytes beginning with the PNG signature.

    Returns:
        tuple[int, int]: The ``(width, height)`` from the IHDR chunk.

    Raises:
        ValueError: If the data does not start with the PNG signature.
    """
    if not data.startswith(_PNG_SIGNATURE):
        msg = "frame is not PNG-compressed (missing PNG signature)"
        raise ValueError(msg)
    width, height = struct.unpack_from(">II", data, 16)
    return width, height


def test_app_icon_is_crisp_multiframe_ico() -> None:
    """The app icon must carry all expected frames with a real 256px PNG master.

    A regression to a single frame, a missing size, or an upscaled/blurred
    master (the earlier 64px-fallback bug) changes the frame set or the master
    frame's format and fails this gate.
    """
    data = _app_icon_path().read_bytes()
    frames = _parse_ico_frames(data)

    sizes = {width for width, _size, _offset in frames}
    assert sizes == _EXPECTED_FRAME_SIZES, f"icon frame sizes {sorted(sizes)} != {sorted(_EXPECTED_FRAME_SIZES)}"

    master = next((f for f in frames if f[0] == _MASTER_FRAME_SIZE), None)
    assert master is not None, "icon.ico has no 256px master frame"
    _width, size, offset = master
    master_bytes = data[offset : offset + size]
    assert master_bytes.startswith(_PNG_SIGNATURE), "256px master frame is not PNG-compressed"
    assert _png_dimensions(master_bytes) == (
        _MASTER_FRAME_SIZE,
        _MASTER_FRAME_SIZE,
    ), "256px master frame does not decode to a true 256x256 image"


def test_rebranded_tool_icon_matches_app_icon() -> None:
    """The AdobeInjector tool icon must stay byte-identical to the app icon.

    Both are the same Intellicrack brand mark; if the app icon is corrected the
    tool copy must be updated in lockstep, or the project ships two spellings of
    the wordmark. Divergent bytes fail this gate.
    """
    app_icon = _app_icon_path().read_bytes()
    tool_icon = _rebranded_tool_icon_path().read_bytes()
    assert tool_icon == app_icon, "rebranded AdobeInjector icon diverged from the app icon (brand drift)"
