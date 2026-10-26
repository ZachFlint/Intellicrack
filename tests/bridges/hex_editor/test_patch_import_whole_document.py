# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gates for whole-document patch application and bounded overwrites in the bridge.

The generic ``HexEditorBridge.import_patches`` dispatcher used to apply a
decoded BPS/UPS target with ``document.write_bytes(0, target)``. An overwrite
never grows a document, so a patch whose target is longer than the source
lost its tail and one whose target is shorter kept the stale tail, while the
call still reported one applied patch. The bridge's ``write_bytes`` likewise
reported success for a write the engine had clamped. These tests drive the
real bridge and the real Rust ``HexDocument``.
"""

from __future__ import annotations

import asyncio
import base64
from typing import TYPE_CHECKING

import pytest
from intellicrack_hexcore import HexDocument

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from pathlib import Path


def _bridge_over(path: Path) -> HexEditorBridge:
    """Open ``path`` in a fresh bridge.

    Args:
        path: File to open.

    Returns:
        HexEditorBridge: Bridge whose document is the opened file.
    """
    bridge = HexEditorBridge()
    bridge.document = HexDocument.open(str(path))
    return bridge


@pytest.mark.parametrize(
    ("source", "target", "is_bps"),
    [
        (b"ABCD", b"ABCDEFGH", True),
        (b"ABCDEFGH", b"AB", True),
        (b"ABCD", b"ABCDEFGH", False),
        (b"ABCDEFGH", b"AB", False),
    ],
    ids=["bps-grow", "bps-shrink", "ups-grow", "ups-shrink"],
)
def test_generic_import_applies_whole_target_length(tmp_path: Path, source: bytes, target: bytes, *, is_bps: bool) -> None:
    """A BPS/UPS patch through the generic dispatcher reproduces the target exactly.

    Applying the target with ``write_bytes(0, target)`` leaves the
    source length in place, so the grow cases read ``b"ABCD"`` and the shrink
    cases keep ``b"CDEFGH"`` after the new bytes.

    Args:
        tmp_path: Pytest temporary directory.
        source: Bytes the patch is built against.
        target: Bytes the patch produces.
        is_bps: True for a BPS patch, False for UPS.
    """
    original = tmp_path / "original.bin"
    original.write_bytes(source)
    target_doc = HexDocument.open_bytes(target)
    patch = target_doc.export_patches_bps(source) if is_bps else target_doc.export_patches_ups(source)

    bridge = _bridge_over(original)
    applied = asyncio.run(bridge.import_patches(base64.b64encode(patch).decode("ascii"), str(original)))

    assert applied == 1
    assert bridge.document is not None
    assert bridge.document.length() == len(target)
    assert bridge.document.read(0, 64) == target
    assert bridge.document.file_path() == str(original)
    assert bridge.document.undo() is True
    assert bridge.document.read(0, 64) == source


def test_generic_import_rejects_patch_for_another_source(tmp_path: Path) -> None:
    """A patch built against different source bytes is refused and changes nothing.

    Args:
        tmp_path: Pytest temporary directory.
    """
    original = tmp_path / "original.bin"
    original.write_bytes(b"ABCD")
    patch = HexDocument.open_bytes(b"ABCDEFGH").export_patches_bps(b"WXYZ")

    bridge = _bridge_over(original)
    with pytest.raises(ToolError, match="invalid BPS patch"):
        asyncio.run(bridge.import_patches(base64.b64encode(patch).decode("ascii"), str(original)))
    assert bridge.document is not None
    assert bridge.document.read(0, 64) == b"ABCD"
    assert bridge.document.can_undo() is False


def test_write_bytes_past_end_raises_and_leaves_document_unchanged(tmp_path: Path) -> None:
    """An overwrite that would run past the end is reported, not silently clamped.

    Without the length check the engine writes the first two
    bytes, drops the rest, and the bridge returns True.

    Args:
        tmp_path: Pytest temporary directory.
    """
    path = tmp_path / "doc.bin"
    path.write_bytes(b"ABCDEFGH")
    bridge = _bridge_over(path)

    with pytest.raises(ValueError, match="runs past the end of the 8-byte document"):
        asyncio.run(bridge.write_bytes(6, "AA BB CC"))
    assert bridge.document is not None
    assert bridge.document.read(0, 8) == b"ABCDEFGH"
    assert asyncio.run(bridge.write_bytes(6, "AA BB")) is True
    assert bridge.document.read(0, 8) == b"ABCDEF\xaa\xbb"
