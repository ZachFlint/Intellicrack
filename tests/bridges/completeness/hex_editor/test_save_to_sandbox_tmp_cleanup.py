# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gate for temp-file cleanup in ``HexEditorBridge.save_to_sandbox``.

When the open document has never been written to disk, ``save_to_sandbox``
materialises it to a ``tempfile.mkstemp`` path so the sandbox bridge has a real
host file to copy. ``HexDocument.save`` leaves that temp file memory-mapped by
the document, so on Windows the ``finally``-block ``unlink`` failed with
``PermissionError: [WinError 5]``; the error was swallowed into a
``tmp_file_cleanup_failed`` warning and the temp file leaked on every call.

The remediation calls ``HexDocument.close()`` before the unlink, releasing the
mapping (the document keeps its bytes in an owned buffer) so the delete
succeeds. These tests drive the real ``HexEditorBridge`` and the real Rust
``HexDocument``; only the sandbox-VM boundary is faked, because provisioning a
Windows Sandbox or QEMU VM cannot run inside the Docker test sandbox.
"""

from __future__ import annotations

import asyncio
import posixpath
from pathlib import Path

import intellicrack_hexcore

from intellicrack.bridges.hex_editor import HexEditorBridge

from .conftest import FakeSandboxBridge, make_registry_with_sandbox


_SANDBOX_DEST_PATH: str = posixpath.join("/", "tmp", "target.bin")
"""Destination path inside the (fake) sandbox container, not a host temp file."""

_DOCUMENT_BYTES: bytes = b"UNSAVED IN-MEMORY DOCUMENT CONTENT"


def _make_bridge_with_in_memory_document() -> tuple[HexEditorBridge, FakeSandboxBridge]:
    """Build a bridge holding an unsaved in-memory document.

    Returns:
        tuple[HexEditorBridge, FakeSandboxBridge]: The bridge under test and the
        fake sandbox collaborator registered on its tool registry.
    """
    fake = FakeSandboxBridge()
    bridge = HexEditorBridge()
    bridge.tool_registry = make_registry_with_sandbox(fake)
    bridge.document = intellicrack_hexcore.HexDocument.open_bytes(_DOCUMENT_BYTES)
    assert bridge.document is not None
    assert bridge.document.file_path() is None, "document must start unsaved for this path to run"
    return bridge, fake


def test_save_to_sandbox_deletes_the_temp_file_it_created() -> None:
    """The temp file materialised for an unsaved document must not leak.

    Falsifiable: without the ``document.close()`` that releases the memory map,
    the ``finally`` block's ``unlink`` raises ``PermissionError`` on Windows,
    is swallowed into a warning, and the asserted path still exists.
    """
    bridge, fake = _make_bridge_with_in_memory_document()

    result = asyncio.run(bridge.save_to_sandbox(_SANDBOX_DEST_PATH))

    assert result["status"] == "copied"
    assert len(fake.copy_calls) == 1, "the document must have been copied into the sandbox"

    tmp_source = Path(fake.copy_calls[0]["source"])
    assert not tmp_source.exists(), f"temp file leaked after save_to_sandbox: {tmp_source}"


def test_save_to_sandbox_copies_real_document_bytes_and_leaves_document_usable() -> None:
    """The copied temp file must hold the real bytes, and the document must survive.

    Guards against a cleanup that "succeeds" by never writing real content, and
    against ``close()`` damaging the still-open document: the bridge's document
    must still read back its full contents after the call.
    """
    bridge, fake = _make_bridge_with_in_memory_document()

    fake.capture_source_bytes = True

    asyncio.run(bridge.save_to_sandbox(_SANDBOX_DEST_PATH))

    assert fake.copied_payloads == [_DOCUMENT_BYTES], (
        "the sandbox must receive the real document bytes"
    )

    assert bridge.document is not None
    assert bridge.document.read(0, bridge.document.length()) == _DOCUMENT_BYTES, (
        "closing the map must not disturb the open document's content"
    )
