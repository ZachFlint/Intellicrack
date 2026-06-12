# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit4 C6 regression tests for the hex editor hashing mixin.

Covers the two findings shipped together in audit4 unit C6:

* **F-0003** -- ``HashingMixin._on_repair_pe_checksum`` must publish a
  :meth:`HexDocumentState.notify_data_modified` event after the
  document write so observers (the hex viewport, the bridge layer,
  the AI tool registry) update instead of displaying the stale
  ``CheckSum`` value.
* **F-0022** -- ``HashingMixin._on_custom_crc`` must offload the CRC
  computation onto a :class:`GenericCallableWorker` and stream the
  document in bounded chunks (mmap for file-backed documents, the
  document API otherwise) instead of slurping the full payload onto
  the UI thread.

**Repair-flow gate (04-F1 / 04-F2):** earlier revisions used a
``StubPeDocument`` whose ``repair_pe_checksum`` wrote a hardcoded
magic constant (``0xC0FFEE42``) and whose ``verify_pe_checksum``
always reported ``calculated=0xC0FFEE42`` so ``valid`` was trivially
``True``.  The stub is now replaced by a real MS PE checksum
implementation cross-validated against :func:`pefile.generate_checksum`
so that breaking the repair logic causes the checksum-value assertion
to go red.

**Production defect P-001 (FIXED):** ``HashingMixin._on_repair_pe_checksum``
previously emitted ``notify_data_modified`` with a hard-coded offset ``0x58``
regardless of where the ``CheckSum`` field actually lived.  It now derives the
offset from ``e_lfanew`` (``_pe_checksum_field_offset``), so for a PE with
``e_lfanew=0x40`` it correctly reports ``0x98``.  ``test_insert_hash_fires_notify``
and ``test_repair_notifies_correct_bytes`` assert that derived offset and would
go red if the constant-offset regression returned.
"""

from __future__ import annotations

import struct
import tracemalloc
from typing import TYPE_CHECKING, Any, cast

import pefile
import pytest
from PyQt6.QtWidgets import QMessageBox, QWidget

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.ui.panels.hex_editor.base import (
    compute_custom_crc,
    compute_streaming_custom_crc,
)
from intellicrack.ui.panels.hex_editor.hashing import HashingMixin
from intellicrack.ui.panels.hex_editor.widgets import CustomCrcDialog


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


# ---------------------------------------------------------------------------
# CRC-32 parameters used throughout (standard zlib / PKZIP CRC-32)
# ---------------------------------------------------------------------------

_CRC32_WIDTH: int = 32
_CRC32_POLY: int = 0x04C11DB7
_CRC32_INIT: int = 0xFFFFFFFF
_CRC32_XOR_OUT: int = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# Minimal valid PE32 construction helpers
# ---------------------------------------------------------------------------

#: ``e_lfanew`` value used by the synthetic PE created in these tests.
_E_LFANEW: int = 0x40

#: Byte offset of the ``CheckSum`` field for a PE with ``e_lfanew=0x40``.
#: Formula: ``e_lfanew + 4 (PE sig) + 20 (COFF) + 64 (into optional header)``.
_REAL_PE_CHECKSUM_OFFSET: int = _E_LFANEW + 4 + 20 + 64  # = 0x98 = 152


def _build_minimal_pe32() -> bytes:
    """Construct a minimal valid PE32 image with the checksum field zeroed.

    The image satisfies :func:`pefile.PE` parsing without errors beyond
    cosmetic warnings about null content.  The ``CheckSum`` field at
    offset :data:`_REAL_PE_CHECKSUM_OFFSET` is intentionally zeroed so
    tests can verify that ``repair_pe_checksum`` writes the correct value.

    Returns:
        bytes: Raw bytes of the minimal PE32 image.
    """
    dos_stub = bytearray(64)
    dos_stub[0:2] = b"MZ"
    struct.pack_into("<I", dos_stub, 0x3C, _E_LFANEW)

    pe_sig = b"PE\x00\x00"

    optional_header_size = 224  # 96 standard fields + 128 data directories
    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,  # machine = IMAGE_FILE_MACHINE_I386
        0,  # num_sections
        0,  # timestamp
        0,  # sym_table_ptr
        0,  # num_symbols
        optional_header_size,
        0x0102,  # characteristics: executable + 32-bit
    )

    headers_size = _E_LFANEW + 4 + 20 + optional_header_size
    image_size = 0x2000

    opt: bytes = b""
    opt += struct.pack("<H", 0x010B)  # Magic: PE32
    opt += struct.pack("<BB", 14, 0)  # linker version
    opt += struct.pack("<III", 0, 0, 0)  # code/initdata/uninitdata sizes
    opt += struct.pack("<III", 0x1000, 0x1000, 0)  # EP, base_of_code, base_of_data
    opt += struct.pack("<I", 0x00400000)  # ImageBase
    opt += struct.pack("<II", 0x1000, 0x0200)  # SectionAlignment, FileAlignment
    opt += struct.pack("<HHHHHH", 4, 0, 1, 0, 2, 0)  # OS/Image/Subsystem versions
    opt += struct.pack("<I", 0)  # Win32VersionValue
    opt += struct.pack("<II", image_size, headers_size)  # SizeOfImage, SizeOfHeaders
    opt += struct.pack("<I", 0)  # CheckSum (zeroed intentionally)
    opt += struct.pack("<H", 2)  # Subsystem: Windows GUI
    opt += struct.pack("<H", 0)  # DllCharacteristics
    opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)  # stack/heap
    opt += struct.pack("<II", 0, 16)  # LoaderFlags, NumberOfRvaAndSizes
    opt += b"\x00" * 128  # 16 data directory entries

    assert len(opt) == optional_header_size, f"opt header size: {len(opt)} != {optional_header_size}"

    return bytes(dos_stub) + pe_sig + coff_header + opt


def _pefile_expected_checksum(pe_bytes: bytes) -> int:
    """Return the MS PE checksum for ``pe_bytes`` via :func:`pefile.generate_checksum`.

    This is the independent oracle used to validate :meth:`StubPeDocument.repair_pe_checksum`.

    Args:
        pe_bytes: Raw bytes of the PE image.  The ``CheckSum`` field may hold any value;
            :func:`pefile.generate_checksum` zeroes it internally before computing.

    Returns:
        int: The correct four-byte PE checksum value.
    """
    pe = pefile.PE(data=pe_bytes)
    try:
        return int(pe.generate_checksum())
    finally:
        pe.close()


def _ms_pe_checksum(file_data: bytes, checksum_offset: int) -> int:
    """Compute the Microsoft PE checksum per the documented algorithm.

    The checksum field at ``checksum_offset`` is zeroed before summation
    so the function is idempotent regardless of what is currently stored there.
    The algorithm is: sum all 16-bit little-endian words with carry folding,
    then add the file length.

    Args:
        file_data: Raw bytes of the PE image.
        checksum_offset: Byte offset of the four-byte ``CheckSum`` field.

    Returns:
        int: The correct four-byte PE checksum value (fits in a 32-bit unsigned).
    """
    data = bytearray(file_data)
    struct.pack_into("<I", data, checksum_offset, 0)
    if len(data) % 2:
        data += b"\x00"
    acc = 0
    for i in range(0, len(data), 2):
        acc += struct.unpack_from("<H", data, i)[0]
        if acc >= 0x100000000:
            acc = (acc & 0xFFFFFFFF) + (acc >> 32)
    acc = (acc & 0xFFFF) + (acc >> 16)
    acc += acc >> 16
    acc &= 0xFFFF
    acc += len(file_data)
    return acc


# ---------------------------------------------------------------------------
# StubPeDocument: in-memory document with REAL PE checksum logic
# ---------------------------------------------------------------------------


class StubPeDocument:
    """In-memory document exposing the methods the hashing mixin uses.

    Mirrors the surface that ``HexDocumentFull``-style documents expose
    so the hashing mixin can drive ``repair_pe_checksum``,
    ``verify_pe_checksum``, ``length``, ``read`` and ``file_path``
    without needing the real Rust hexcore module loaded.

    Unlike the earlier stub, ``repair_pe_checksum`` computes the actual
    Microsoft PE checksum using :func:`_ms_pe_checksum` and writes it to the
    real checksum field offset derived from ``e_lfanew``.
    ``verify_pe_checksum`` then independently re-computes and compares.
    Both implementations are cross-validated against :func:`pefile.generate_checksum`
    in the test suite.
    """

    def __init__(self, data: bytes, *, file_path: str | None = None) -> None:
        """Capture the initial bytes and optional backing path.

        Args:
            data: Initial document content.  Must be a valid PE image if
                ``repair_pe_checksum`` or ``verify_pe_checksum`` will be called;
                the stub reads ``e_lfanew`` from offset ``0x3C`` to locate the
                checksum field.
            file_path: Optional path returned by ``file_path()`` so the
                streaming CRC source can prefer mmap.
        """
        self._data: bytearray = bytearray(data)
        self._file_path: str | None = file_path
        self.repair_calls: int = 0
        self.verify_calls: int = 0

    def _checksum_offset(self) -> int:
        """Derive the checksum field offset from ``e_lfanew`` in the DOS header.

        Returns:
            int: Byte offset of the four-byte ``CheckSum`` field within the document.

        Raises:
            ValueError: When the document is too small to contain a valid DOS or
                PE optional header.
        """
        if len(self._data) < 0x40:
            msg = f"document too small to contain a DOS header: {len(self._data)} bytes"
            raise ValueError(msg)
        e_lfanew: int = struct.unpack_from("<I", self._data, 0x3C)[0]
        # PE sig (4) + COFF (20) + 64 bytes into optional header = checksum
        offset = e_lfanew + 4 + 20 + 64
        if offset + 4 > len(self._data):
            msg = f"document too small for PE checksum at offset {offset:#x}: {len(self._data)} bytes"
            raise ValueError(msg)
        return offset

    def length(self) -> int:
        """Return the current document length in bytes.

        Returns:
            int: Number of bytes currently held.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        """Return ``[offset, offset+length)`` from the document.

        Args:
            offset: Inclusive start offset.
            length: Number of bytes to copy.

        Returns:
            bytes: Slice of the document content.
        """
        return bytes(self._data[offset : offset + length])

    def file_path(self) -> str | None:
        """Return the on-disk path backing this document.

        Returns:
            str | None: Path passed to the constructor or ``None``.
        """
        return self._file_path

    def repair_pe_checksum(self) -> None:
        """Compute the real MS PE checksum and write it to the checksum field.

        Uses the documented Microsoft PE checksum algorithm
        (:func:`_ms_pe_checksum`) to compute the correct four-byte
        value and overwrites the ``CheckSum`` field at the offset
        derived from ``e_lfanew``.  This matches the behaviour of the
        real hexcore ``HexDocument.repair_pe_checksum()`` method as
        confirmed by :func:`pefile.generate_checksum`.
        """
        self.repair_calls += 1
        chk_off = self._checksum_offset()
        correct = _ms_pe_checksum(bytes(self._data), chk_off)
        struct.pack_into("<I", self._data, chk_off, correct)

    def verify_pe_checksum(self) -> dict[str, Any]:
        """Return verification metadata comparing stored vs. computed checksum.

        Returns:
            dict[str, Any]: Mapping with ``stored`` (the value currently in the
                checksum field), ``calculated`` (the value the algorithm computes
                for the current file content with the checksum field zeroed),
                ``offset`` (byte offset of the field), and ``valid``
                (``True`` iff ``stored == calculated``).
        """
        self.verify_calls += 1
        chk_off = self._checksum_offset()
        stored = struct.unpack_from("<I", self._data, chk_off)[0]
        calculated = _ms_pe_checksum(bytes(self._data), chk_off)
        return {
            "stored": stored,
            "calculated": calculated,
            "offset": chk_off,
            "valid": stored == calculated,
        }

    def write_bytes(self, offset: int, data: bytes) -> None:
        """Overwrite bytes in the document at ``offset``.

        Provided as a test helper so tests can inject corrupt data without
        accessing the internal ``_data`` bytearray directly (which would
        trigger basedpyright ``reportPrivateUsage``).

        Args:
            offset: Start offset of the region to overwrite.
            data: Bytes to write; must fit within ``[offset, offset+len(data))``.
        """
        self._data[offset : offset + len(data)] = data


# ---------------------------------------------------------------------------
# HashingHarness: concrete HashingMixin consumer for tests
# ---------------------------------------------------------------------------


class HashingHarness(QWidget, HashingMixin):
    """Concrete ``HashingMixin`` consumer used by the regression tests.

    Provides the attribute slots the mixin's type stubs declare so that
    direct attribute access in ``HashingMixin`` resolves at runtime
    without raising ``AttributeError``.
    """

    def __init__(
        self,
        *,
        document: StubPeDocument,
        state_holder: HexDocumentState,
        file_path: Path | None = None,
    ) -> None:
        """Wire the mixin slots up to test-supplied collaborators.

        Args:
            document: Object exposing the hashing-mixin document
                surface (``length``, ``read``, ``repair_pe_checksum``,
                ``verify_pe_checksum``, ``file_path``).
            state_holder: Real :class:`HexDocumentState` whose
                ``notify_data_modified`` calls the test asserts on.
            file_path: Optional panel-side ``file_path`` attribute the
                mixin checks before falling back to ``document.file_path()``.
        """
        QWidget.__init__(self)
        self._document: StubPeDocument = document
        self.document: StubPeDocument = document
        self._hex_widget = None
        self._hash_algo_combo = None
        self._hash_result_label = None
        self._selection_start: int = -1
        self._selection_end: int = -1
        self._pe_checksum_status = None
        self.state_holder: HexDocumentState | None = state_holder
        self.file_path: Path | None = file_path
        self._custom_crc_worker = None

    def repair_pe_checksum(self) -> None:
        """Invoke the mixin repair flow as a public test entry point.

        Delegates directly to :meth:`HashingMixin._on_repair_pe_checksum`
        so tests drive the full code path through a public API without
        triggering basedpyright ``reportPrivateUsage`` diagnostics.
        """
        self._on_repair_pe_checksum()

    def resolve_custom_crc_file_path(self) -> str | None:
        """Return the mixin's resolved CRC file path via a public entry point.

        Delegates directly to
        :meth:`HashingMixin._resolve_custom_crc_file_path` so tests can
        assert the resolved path without triggering basedpyright
        ``reportPrivateUsage`` diagnostics.

        Returns:
            str | None: Absolute path of an existing readable file,
                or ``None`` when the document has no usable file backing.
        """
        return self._resolve_custom_crc_file_path()


# ---------------------------------------------------------------------------
# NotifyRecorder
# ---------------------------------------------------------------------------


class NotifyRecorder:
    """Capture every ``notify_*`` event emitted on a state holder."""

    def __init__(self) -> None:
        """Initialise the recorder with an empty event list."""
        self.events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

    def __call__(self, event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
        """Append the received event to the recorder.

        Args:
            event_type: Event type emitted by the state holder.
            data: Payload dict supplied with the event.
        """
        self.events.append((event_type, dict(data)))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def message_box_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force every ``QMessageBox.question`` call to return ``Yes``.

    The repair flow asks the user to confirm overwriting the PE
    ``CheckSum`` field; the regression test must approve the prompt
    without manual interaction.  ``monkeypatch`` undoes the patch
    automatically on test teardown so the fixture body itself only
    needs to install it.

    Args:
        monkeypatch: pytest monkeypatch fixture used to patch the
            ``QMessageBox.question`` static method for the duration
            of one test.
    """

    def _fake_question(
        _parent: QWidget | None,
        _title: str,
        _text: str,
        *_args: object,
        **_kwargs: object,
    ) -> QMessageBox.StandardButton:
        """Return ``Yes`` so the repair confirmation prompt always passes.

        Args:
            _parent: Ignored parent widget.
            _title: Ignored dialog title.
            _text: Ignored dialog body text.
            *_args: Ignored extra positional arguments.
            **_kwargs: Ignored keyword arguments.

        Returns:
            QMessageBox.StandardButton: The ``Yes`` enum value.
        """
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(QMessageBox, "question", _fake_question)


# ---------------------------------------------------------------------------
# TestStubPeDocumentChecksumLogic: verify the stub itself is a real oracle
# ---------------------------------------------------------------------------


class TestStubPeDocumentChecksumLogic:
    """Verify that the stub's PE checksum implementation matches pefile.

    These tests validate the oracle used by the repair-gate tests.
    If the stub's checksum algorithm diverges from pefile the repair
    tests would be checking against an incorrect expected value.
    """

    @staticmethod
    def test_ms_pe_checksum_matches_pefile_oracle() -> None:
        """``_ms_pe_checksum`` produces the identical value as ``pefile.generate_checksum``.

        Uses a minimal but valid PE32 binary with the checksum field deliberately
        zeroed.  The independent oracle (:func:`pefile.generate_checksum`) is
        compared against our implementation to confirm they agree before either
        is used as the expected value in repair-flow tests.
        """
        pe_bytes = _build_minimal_pe32()
        our_value = _ms_pe_checksum(pe_bytes, _REAL_PE_CHECKSUM_OFFSET)
        pefile_value = _pefile_expected_checksum(pe_bytes)

        assert our_value == pefile_value, (
            f"_ms_pe_checksum produced 0x{our_value:08X} but pefile.generate_checksum "
            f"produced 0x{pefile_value:08X} for the same minimal PE32 image"
        )
        assert our_value != 0, "checksum of a non-empty file cannot be zero"

    @staticmethod
    def test_stub_repair_writes_correct_checksum() -> None:
        """``StubPeDocument.repair_pe_checksum`` writes the pefile-correct checksum.

        Before repair the checksum field is zero (intentionally).  After repair
        the four bytes at :data:`_REAL_PE_CHECKSUM_OFFSET` must equal the value
        that :func:`pefile.generate_checksum` computes for the same image.
        """
        pe_bytes = _build_minimal_pe32()
        doc = StubPeDocument(pe_bytes)

        stored_before = struct.unpack_from("<I", doc.read(0, len(pe_bytes)), _REAL_PE_CHECKSUM_OFFSET)[0]
        assert stored_before == 0, "sanity: synthetic PE must start with a zeroed checksum"

        doc.repair_pe_checksum()

        stored_after = struct.unpack_from("<I", doc.read(0, len(pe_bytes)), _REAL_PE_CHECKSUM_OFFSET)[0]
        expected = _pefile_expected_checksum(pe_bytes)

        assert stored_after == expected, (
            f"repair_pe_checksum wrote 0x{stored_after:08X} to offset "
            f"0x{_REAL_PE_CHECKSUM_OFFSET:X} but pefile oracle says the correct value "
            f"is 0x{expected:08X}"
        )

    @staticmethod
    def test_stub_verify_detects_correct_checksum_after_repair() -> None:
        """``StubPeDocument.verify_pe_checksum`` returns ``valid=True`` after repair.

        Validates the full repair-then-verify cycle.  The ``stored`` value
        returned by ``verify_pe_checksum`` must equal the pefile-computed checksum
        and ``valid`` must be ``True``.
        """
        pe_bytes = _build_minimal_pe32()
        doc = StubPeDocument(pe_bytes)
        doc.repair_pe_checksum()

        info = doc.verify_pe_checksum()
        expected = _pefile_expected_checksum(pe_bytes)

        assert info["valid"] is True, f"verify_pe_checksum reported invalid after repair: {info}"
        assert info["stored"] == expected, f"stored checksum 0x{info['stored']:08X} != pefile oracle 0x{expected:08X}"
        assert info["calculated"] == expected, f"calculated checksum 0x{info['calculated']:08X} != pefile oracle 0x{expected:08X}"
        assert info["offset"] == _REAL_PE_CHECKSUM_OFFSET, (
            f"verify_pe_checksum reported offset {info['offset']:#x} but expected {_REAL_PE_CHECKSUM_OFFSET:#x}"
        )

    @staticmethod
    def test_stub_verify_detects_wrong_checksum() -> None:
        """``StubPeDocument.verify_pe_checksum`` returns ``valid=False`` for a corrupt checksum.

        Manually writes a wrong value to the checksum field and confirms that
        ``verify_pe_checksum`` detects the mismatch.  This test proves the stub
        cannot produce a false ``valid=True`` from a self-consistent magic constant.
        """
        pe_bytes = _build_minimal_pe32()
        doc = StubPeDocument(pe_bytes)

        corrupt_value = 0xDEADBEEF
        doc.write_bytes(_REAL_PE_CHECKSUM_OFFSET, struct.pack("<I", corrupt_value))

        info = doc.verify_pe_checksum()
        expected = _pefile_expected_checksum(pe_bytes)

        assert info["valid"] is False, "verify_pe_checksum must detect a deliberately corrupt checksum"
        assert info["stored"] == corrupt_value
        assert info["calculated"] == expected


# ---------------------------------------------------------------------------
# TestRepairPeChecksumFiresNotify: F-0003 gate
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("qapp", "message_box_yes")
class TestRepairPeChecksumFiresNotify:
    """F-0003 -- ``_on_repair_pe_checksum`` must call ``notify_data_modified``.

    These tests use a minimal but valid PE32 image so the stub's real checksum
    algorithm runs on genuine PE structure rather than an arbitrary byte buffer.
    """

    @staticmethod
    def test_insert_hash_fires_notify() -> None:
        """Driving the repair action emits one ``DATA_MODIFIED`` event.

        The recorded event must reference the real ``CheckSum`` field offset
        derived from ``e_lfanew`` (``_REAL_PE_CHECKSUM_OFFSET = 0x98`` for this
        ``e_lfanew=0x40`` image) and a four-byte field width.  The actual PE
        checksum bytes written by the document are asserted against the
        independent :func:`pefile.generate_checksum` oracle to prove the repair
        did real work, not just a write of a magic constant.
        """
        pe_bytes = _build_minimal_pe32()
        document = StubPeDocument(pe_bytes)
        state = HexDocumentState()

        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")
        harness = HashingHarness(document=document, state_holder=state)
        try:
            harness.repair_pe_checksum()
        finally:
            harness.deleteLater()

        assert document.repair_calls == 1, "repair_pe_checksum was not called exactly once"

        data_events = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.DATA_MODIFIED]
        assert len(data_events) == 1, f"expected exactly one DATA_MODIFIED event, got {recorder.events}"
        _, payload = data_events[0]

        assert payload["offset"] == _REAL_PE_CHECKSUM_OFFSET, (
            f"notify offset {payload['offset']:#x} != real checksum field offset {_REAL_PE_CHECKSUM_OFFSET:#x}"
        )
        assert payload["length"] == 4

        # Verify the BYTES actually written by the document match the pefile oracle.
        repaired_raw = document.read(0, document.length())
        written_checksum = struct.unpack_from("<I", repaired_raw, _REAL_PE_CHECKSUM_OFFSET)[0]
        expected_checksum = _pefile_expected_checksum(pe_bytes)
        assert written_checksum == expected_checksum, (
            f"repair wrote 0x{written_checksum:08X} at offset {_REAL_PE_CHECKSUM_OFFSET:#x} "
            f"but pefile oracle expects 0x{expected_checksum:08X}"
        )

    @staticmethod
    def test_repair_uses_audit_defined_source_identifier() -> None:
        """The ``source`` argument lets the loop guard suppress the echo.

        Registering the recorder with the same ``source_id`` the mixin
        passes to ``notify_data_modified`` proves the mixin used the
        documented identifier instead of an unrelated string.
        """
        pe_bytes = _build_minimal_pe32()
        document = StubPeDocument(pe_bytes)
        state = HexDocumentState()

        recorder = NotifyRecorder()
        state.register_callback(
            recorder,
            source_id="hex-editor.hashing.repair_pe_checksum",
        )
        harness = HashingHarness(document=document, state_holder=state)
        try:
            harness.repair_pe_checksum()
        finally:
            harness.deleteLater()

        data_events = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.DATA_MODIFIED]
        assert data_events == [], (
            "expected the loop-guard filter to suppress the data_modified echo when the recorder "
            "registers with the same source_id, but received: " + repr(data_events)
        )

    @staticmethod
    def test_repair_notifies_correct_bytes() -> None:
        """The ``notify_data_modified`` offset must equal the actual PE checksum field offset.

        ``HashingMixin._on_repair_pe_checksum`` reads ``e_lfanew`` from the
        document (``_pe_checksum_field_offset``) to locate the ``CheckSum`` field
        rather than assuming a fixed constant.  For the minimal PE32 used here
        (``e_lfanew=0x40``) the correct offset is ``0x98``
        (= :data:`_REAL_PE_CHECKSUM_OFFSET`).  This gate would go red if the code
        regressed to a hard-coded offset (the original P-001 defect).
        """
        pe_bytes = _build_minimal_pe32()
        document = StubPeDocument(pe_bytes)
        state = HexDocumentState()

        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")
        harness = HashingHarness(document=document, state_holder=state)
        try:
            harness.repair_pe_checksum()
        finally:
            harness.deleteLater()

        data_events = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.DATA_MODIFIED]
        assert len(data_events) == 1
        _, payload = data_events[0]

        # The notification offset must match the real checksum field location,
        # derived from e_lfanew rather than a fixed constant.
        assert payload["offset"] == _REAL_PE_CHECKSUM_OFFSET, (
            f"notify_data_modified reported offset {payload['offset']:#x} but the "
            f"actual PE checksum field for this image (e_lfanew=0x{_E_LFANEW:02X}) "
            f"is at offset {_REAL_PE_CHECKSUM_OFFSET:#x}.  "
            f"Production defect P-001: hashing.py uses a hardcoded 0x58 constant "
            f"instead of deriving the offset from e_lfanew."
        )


# ---------------------------------------------------------------------------
# TestCustomCrcOffloaded: F-0022 gate
# ---------------------------------------------------------------------------


def _build_synthetic_payload(size: int) -> bytes:
    """Return ``size`` bytes of a deterministic repeating pattern.

    Uses the byte sequence ``[0..255]`` repeated to fill ``size`` bytes
    so the same file produces the same CRC across runs.

    Args:
        size: Number of bytes in the returned payload.

    Returns:
        bytes: ``size``-long deterministic payload.
    """
    pattern: bytes = bytes(range(256))
    repeats: int = size // len(pattern)
    body: bytes = pattern * repeats + pattern[: size - repeats * len(pattern)]
    assert len(body) == size
    return body


def _run_custom_crc_calc(
    harness: HashingHarness,
    qtbot: QtBot,
) -> tuple[object, tracemalloc.Snapshot]:
    """Construct the CRC dialog, run ``_calculate``, and capture a snapshot.

    Args:
        harness: HashingHarness providing the document and parent widget.
        qtbot: pytest-qt qtbot used to wait on the dialog's signal.

    Returns:
        tuple[object, tracemalloc.Snapshot]: The signal blocker and the
        tracemalloc snapshot taken while the worker was running.
    """
    dlg = CustomCrcDialog(
        file_path=harness.resolve_custom_crc_file_path(),
        document=harness.document,
        length=harness.document.length(),
        parent=harness,
        worker_parent=None,
    )
    _configure_crc_dialog(dlg)

    calculate_fn = getattr(dlg, "_calculate")
    with qtbot.waitSignal(dlg.crc_computed, timeout=120_000) as blocker:
        calculate_fn()
        assert dlg.worker() is not None
        snapshot_during = tracemalloc.take_snapshot()
    return blocker, snapshot_during


def _configure_crc_dialog(dlg: CustomCrcDialog) -> None:
    """Pre-populate ``dlg`` with the test's CRC-32 parameter set.

    Uses ``getattr`` for the dialog's form fields so that basedpyright
    does not emit ``reportPrivateUsage`` diagnostics for the single-
    underscore attributes.

    Args:
        dlg: Dialog whose form widgets are pre-set so the test does
            not depend on dialog defaults that may change.
    """
    poly_edit = getattr(dlg, "_poly_edit")
    init_edit = getattr(dlg, "_init_edit")
    xor_out_edit = getattr(dlg, "_xor_out_edit")
    width_spin = getattr(dlg, "_width_spin")
    ref_in_check = getattr(dlg, "_ref_in_check")
    ref_out_check = getattr(dlg, "_ref_out_check")

    poly_edit.setText(f"{_CRC32_POLY:08X}")
    init_edit.setText(f"{_CRC32_INIT:08X}")
    xor_out_edit.setText(f"{_CRC32_XOR_OUT:08X}")
    width_spin.setValue(_CRC32_WIDTH)
    ref_in_check.setChecked(True)
    ref_out_check.setChecked(True)


@pytest.mark.usefixtures("qapp")
class TestCustomCrcOffloaded:
    """F-0022 -- ``_on_custom_crc`` must offload + stream the CRC."""

    @staticmethod
    def test_custom_crc_offloaded(qtbot: QtBot, tmp_path: Path) -> None:
        """Computing CRC on a 50 MiB file stays under a bounded UI budget.

        The UI thread must not allocate anywhere near 50 MiB while the
        worker streams the file.  ``tracemalloc`` measures peak Python
        allocations on the calling thread between dialog construction
        and worker dispatch; the budget allows for the dialog widgets
        themselves but rejects any code path that copies the file
        body into Python-managed memory on the UI thread.

        Args:
            qtbot: pytest-qt bot fixture used to wait on the dialog
                worker's ``crc_computed`` signal.
            tmp_path: Pytest temporary directory used to stage the
                synthetic 50 MiB document on disk.
        """
        size: int = 50 * 1024 * 1024
        body: bytes = _build_synthetic_payload(size)
        target: Path = tmp_path / "crc_offload_target.bin"
        target.write_bytes(body)

        document = StubPeDocument(body, file_path=str(target))
        harness = HashingHarness(
            document=document,
            state_holder=HexDocumentState(),
            file_path=target,
        )

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()
        try:
            blocker, snapshot_during = _run_custom_crc_calc(harness, qtbot)
        finally:
            tracemalloc.stop()
            harness.deleteLater()

        raw_args: object = getattr(blocker, "args", None)
        crc_value: object = cast("list[object]", raw_args)[0] if isinstance(raw_args, list) and raw_args else None
        assert isinstance(crc_value, int)
        assert crc_value == compute_custom_crc(
            body,
            _CRC32_WIDTH,
            _CRC32_POLY,
            _CRC32_INIT,
            ref_in=True,
            ref_out=True,
            xor_out=_CRC32_XOR_OUT,
        )

        diff = snapshot_during.compare_to(snapshot_before, "lineno")
        ui_growth: int = sum(stat.size_diff for stat in diff if stat.size_diff > 0)
        ui_budget: int = 10 * 1024 * 1024
        assert ui_growth < ui_budget, (
            f"UI thread allocated {ui_growth / (1024 * 1024):.1f} MiB while the worker streamed "
            f"a {size / (1024 * 1024):.0f} MiB document; the budget is "
            f"{ui_budget / (1024 * 1024):.0f} MiB. The dialog must offload + stream, not slurp."
        )

    @staticmethod
    def test_custom_crc_correctness(qtbot: QtBot, tmp_path: Path) -> None:
        """The streaming worker returns the exact reference CRC value.

        Computes the CRC via the offloaded streaming path and compares
        the result against the bit-serial reference shared by the
        dialog's old code path plus two direct invocations of the
        streaming helper (mmap and document-chunk sources) so a
        regression in any branch surfaces independently.

        Args:
            qtbot: pytest-qt bot fixture used to wait on the dialog
                worker's ``crc_computed`` signal.
            tmp_path: Pytest temporary directory used to stage the
                synthetic document on disk.
        """
        body: bytes = b"The quick brown fox jumps over the lazy dog" * 1024
        target: Path = tmp_path / "crc_correctness_target.bin"
        target.write_bytes(body)

        harness = HashingHarness(
            document=StubPeDocument(body, file_path=str(target)),
            state_holder=HexDocumentState(),
            file_path=target,
        )

        try:
            dlg = CustomCrcDialog(
                file_path=harness.resolve_custom_crc_file_path(),
                document=harness.document,
                length=harness.document.length(),
                parent=harness,
                worker_parent=None,
            )
            _configure_crc_dialog(dlg)

            calculate_fn = getattr(dlg, "_calculate")
            with qtbot.waitSignal(dlg.crc_computed, timeout=60_000) as blocker:
                calculate_fn()
        finally:
            harness.deleteLater()

        raw_args: object = getattr(blocker, "args", None)
        args_list: list[object] = list(cast("list[object]", raw_args)) if isinstance(raw_args, list) else []
        crc_value: object = args_list[0] if args_list else None
        assert isinstance(crc_value, int)

        bit_serial_reference: int = compute_custom_crc(
            body,
            _CRC32_WIDTH,
            _CRC32_POLY,
            _CRC32_INIT,
            ref_in=True,
            ref_out=True,
            xor_out=_CRC32_XOR_OUT,
        )
        assert crc_value == bit_serial_reference

        helper_reference_file: int = compute_streaming_custom_crc(
            str(target),
            None,
            _CRC32_WIDTH,
            _CRC32_POLY,
            _CRC32_INIT,
            ref_in=True,
            ref_out=True,
            xor_out=_CRC32_XOR_OUT,
        )
        assert crc_value == helper_reference_file

        helper_reference_doc: int = compute_streaming_custom_crc(
            None,
            StubPeDocument(body),
            _CRC32_WIDTH,
            _CRC32_POLY,
            _CRC32_INIT,
            ref_in=True,
            ref_out=True,
            xor_out=_CRC32_XOR_OUT,
            chunk_size=8192,
        )
        assert helper_reference_doc == bit_serial_reference
