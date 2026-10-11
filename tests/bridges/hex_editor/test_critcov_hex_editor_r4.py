# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Contract tests for ``HexEditorBridge.repair_pe_checksum`` on an image whose stored checksum is wrong.

The bridge documents that the repair returns a dict with ``old_checksum``, ``new_checksum`` and ``offset``, and the tool
description repeats it. The existing suites only repair images whose stored checksum is zero, so a report of ``0`` for the
replaced value cannot be told apart from the right one. Every image here is built by the test with a known non-zero wrong
checksum, and the expected checksum is computed by the test from the published PE algorithm (sum of little-endian 16-bit words
with the checksum field treated as zero, carries folded, plus the file length). The document is a real native
``intellicrack_hexcore.HexDocument`` and the observer is a real ``HexDocumentState``.
"""

from __future__ import annotations

import gc
import struct
from typing import TYPE_CHECKING, Any

import intellicrack_hexcore
import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState


if TYPE_CHECKING:
    from collections.abc import Iterator


_E_LFANEW: int = 0x80
_FIELD: int = _E_LFANEW + 4 + 20 + 64
_FIELD_LEN: int = 4
_BODY_LEN: int = 200
_WRONG_CHECKSUM: int = 0x12345678
_OBSERVER: str = "observer"


class _EventLog:
    """Observer callback that records every event a ``HexDocumentState`` delivers, with a copy of its payload, in order."""

    def __init__(self) -> None:
        """Start with an empty event list."""
        self.events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

    def __call__(self, event: HexDocumentEvent, data: dict[str, Any]) -> None:
        """Record one delivered event.

        Args:
            event: Event kind the state holder emitted.
            data: Payload delivered with the event.
        """
        self.events.append((event, dict(data)))

    def modified(self) -> list[dict[str, Any]]:
        """Return the payloads of the data-modified events seen so far.

        Returns:
            list[dict[str, Any]]: Payload of each ``DATA_MODIFIED`` event, in order.
        """
        return [data for event, data in self.events if event is HexDocumentEvent.DATA_MODIFIED]


def _build_pe(stored: int) -> bytes:
    """Build a PE-shaped image with a patterned body and a chosen stored checksum.

    The layout follows the PE format: a DOS header whose offset 0x3C holds ``e_lfanew``, the four-byte PE signature, a 20-byte
    COFF header and a 224-byte optional header whose ``CheckSum`` field sits 64 bytes in. The total length is even.

    Args:
        stored: Value written into the ``CheckSum`` field.

    Returns:
        bytes: The image.
    """
    image = bytearray((index * 7 + 3) & 0xFF for index in range(_E_LFANEW + 4 + 20 + 224 + _BODY_LEN))
    image[0:2] = b"MZ"
    image[0x3C:0x40] = struct.pack("<I", _E_LFANEW)
    image[_E_LFANEW : _E_LFANEW + 4] = b"PE\x00\x00"
    image[_FIELD : _FIELD + _FIELD_LEN] = struct.pack("<I", stored)
    return bytes(image)


def _pe_checksum(data: bytes, field_offset: int) -> int:
    """Compute the Microsoft PE checksum with the published algorithm.

    All 16-bit little-endian words are summed with the checksum field treated as zero, carries are folded back in, and the
    file length is added.

    Args:
        data: Complete image of even length.
        field_offset: Offset of the four-byte ``CheckSum`` field.

    Returns:
        int: The checksum the field should hold.
    """
    buffer = bytearray(data)
    buffer[field_offset : field_offset + _FIELD_LEN] = b"\x00\x00\x00\x00"
    total = 0
    for (word,) in struct.iter_unpack("<H", bytes(buffer)):
        total += word
        if total >= 0x100000000:
            total = (total & 0xFFFFFFFF) + (total >> 32)
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    total &= 0xFFFF
    return total + len(data)


@pytest.fixture
def hex_bridge() -> Iterator[HexEditorBridge]:
    """Provide an uninitialized ``HexEditorBridge`` and release any document afterwards.

    Yields:
        HexEditorBridge: A bridge with no document attached.
    """
    bridge = HexEditorBridge()
    try:
        yield bridge
    finally:
        bridge.document = None
        gc.collect()


def _attach(bridge: HexEditorBridge, image: bytes) -> intellicrack_hexcore.HexDocument:
    """Attach a real in-memory native document holding ``image`` to ``bridge``.

    Args:
        bridge: Bridge receiving the document.
        image: Document contents.

    Returns:
        intellicrack_hexcore.HexDocument: The attached document.
    """
    document = intellicrack_hexcore.HexDocument.open_bytes(image)
    bridge.document = document
    return document


@pytest.mark.asyncio
async def test_repair_of_a_wrongly_stamped_image_writes_the_correct_checksum_and_reports_new_value_and_offset(
    hex_bridge: HexEditorBridge,
) -> None:
    """The report names the correct checksum and the field's offset, and the document ends up with a valid checksum.

    Args:
        hex_bridge: Bridge under test.
    """
    image = _build_pe(_WRONG_CHECKSUM)
    correct = _pe_checksum(image, _FIELD)
    document = _attach(hex_bridge, image)
    assert correct != _WRONG_CHECKSUM
    assert document.read(_FIELD, _FIELD_LEN) == struct.pack("<I", _WRONG_CHECKSUM)

    result = await hex_bridge.repair_pe_checksum()

    assert set(result) == {"old_checksum", "new_checksum", "offset"}
    assert result["new_checksum"] == correct
    assert result["offset"] == _FIELD
    assert document.read(_FIELD, _FIELD_LEN) == struct.pack("<I", correct)
    verified = document.verify_pe_checksum()
    assert verified["valid"] is True
    assert verified["stored"] == correct
    assert verified["calculated"] == correct
    assert document.read(0, _FIELD) == image[:_FIELD]
    assert document.read(_FIELD + _FIELD_LEN, len(image) - _FIELD - _FIELD_LEN) == image[_FIELD + _FIELD_LEN :]


@pytest.mark.asyncio
@pytest.mark.parametrize("stored", [_WRONG_CHECKSUM, 1, 0xFFFFFFFF])
async def test_repair_reports_the_stored_value_it_replaced_as_old_checksum(
    hex_bridge: HexEditorBridge,
    stored: int,
) -> None:
    """The ``old_checksum`` entry is the value the field held before the repair, as the docstring and tool description promise.

    Args:
        hex_bridge: Bridge under test.
        stored: Non-zero wrong value placed in the image's ``CheckSum`` field.
    """
    image = _build_pe(stored)
    correct = _pe_checksum(image, _FIELD)
    _attach(hex_bridge, image)
    assert stored not in {0, correct}

    result = await hex_bridge.repair_pe_checksum()

    assert result == {"old_checksum": stored, "new_checksum": correct, "offset": _FIELD}


@pytest.mark.asyncio
async def test_repair_notifies_the_attached_state_holder_that_the_checksum_field_changed(hex_bridge: HexEditorBridge) -> None:
    """A repair through the bridge publishes one data-modified event covering the four checksum bytes.

    Expectation grounded on: ``HexDocumentEvent.DATA_MODIFIED`` is documented as "Document bytes were modified";
    ``write_bytes``, ``insert_bytes``, ``delete_bytes`` and the other byte-mutating bridge methods call
    ``state_holder.notify_data_modified(offset, length, source="bridge")``; ``repair_pe_checksum`` is listed among the
    document-mutating hex editor bridge methods in the orchestrator; and the panel's own repair path notifies the same event
    for the same four bytes.

    Args:
        hex_bridge: Bridge under test.
    """
    image = _build_pe(_WRONG_CHECKSUM)
    document = _attach(hex_bridge, image)
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id=_OBSERVER)
    hex_bridge.set_state_holder(holder)

    await hex_bridge.repair_pe_checksum()

    assert document.read(_FIELD, _FIELD_LEN) == struct.pack("<I", _pe_checksum(image, _FIELD))
    assert log.modified() == [{"offset": _FIELD, "length": _FIELD_LEN, "source": "bridge"}]
