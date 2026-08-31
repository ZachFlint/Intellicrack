# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for ``HexDocument.close()`` map-release semantics.

``open`` / ``save`` / ``save_as`` keep the backing file memory-mapped for
zero-copy reads, which on Windows leaves the file locked against deletion or a
truncating rewrite until the document is dropped. ``close()`` copies the
current content into an owned in-memory buffer and unmaps the file, releasing
that lock deterministically while keeping the document fully usable. These
tests drive the real compiled extension against real files on disk: the lock is
observed before ``close()`` and its release is observed after, so a ``close()``
that failed to unmap would redden the gate rather than pass silently.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack_hexcore import HexDocument
else:
    HexDocument = pytest.importorskip(
        "intellicrack_hexcore",
        reason="intellicrack_hexcore native module not built",
    ).HexDocument


def test_close_releases_file_lock_and_keeps_owned_copy(tmp_path: Path) -> None:
    """``close()`` unmaps the file so its path becomes writable again.

    Args:
        tmp_path: Pytest-provided unique temporary directory.
    """
    path = tmp_path / "mapped.bin"
    original = b"ORIGINAL CONTENT 0123456789"
    path.write_bytes(original)

    doc = HexDocument.open(str(path))
    assert doc.read(0, doc.length()) == original

    if sys.platform == "win32":
        # A live mapping locks the file against a truncating rewrite. Proving
        # the lock exists first guards against a vacuous pass where nothing was
        # ever mapped; the write is expected to fail, so a success is a defect.
        locked = False
        try:
            with path.open("wb") as handle:
                handle.write(b"x")
        except OSError:
            locked = True
        assert locked, "a live mapping must lock the file against a truncating rewrite"

    doc.close()

    assert doc.read(0, doc.length()) == original, "close must preserve content in an owned buffer"

    with path.open("wb") as handle:
        handle.write(b"REPLACED CONTENT")
    assert path.read_bytes() == b"REPLACED CONTENT", "file must be writable once the map is released"

    assert doc.read(0, doc.length()) == original, "closed document must keep its own copy"


def test_close_preserves_content_is_idempotent_and_editable(tmp_path: Path) -> None:
    """``close()`` keeps the document readable, re-closable, and editable.

    Args:
        tmp_path: Pytest-provided unique temporary directory.
    """
    path = tmp_path / "content.bin"
    data = bytes(range(256)) * 4
    path.write_bytes(data)

    doc = HexDocument.open(str(path))
    doc.close()

    assert doc.length() == len(data)
    assert doc.read(0, len(data)) == data

    doc.close()
    assert doc.read(0, len(data)) == data, "a second close must not corrupt content"

    doc.write_bytes(0, b"\xff\xff")
    assert doc.read(0, 2) == b"\xff\xff", "document must stay editable after close"
    assert doc.can_undo(), "post-close edits must still record undo history"
