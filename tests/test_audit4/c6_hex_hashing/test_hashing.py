# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit4 C6 regression tests for the hex editor hashing mixin.

Covers the findings shipped together in audit4 unit C6, plus the audit
remediation that replaces the hand-built stub document and the
``QMessageBox.question`` monkeypatch with real collaborators:

* **F-0003** -- ``HashingMixin._on_repair_pe_checksum`` must publish a
  :meth:`HexDocumentState.notify_data_modified` event after the document
  write so observers (the hex viewport, the bridge layer, the AI tool
  registry) update instead of displaying the stale ``CheckSum`` value. The
  repair must also stay gated behind the real ``QMessageBox`` confirmation:
  these tests drive the real dialog by clicking its real ``Yes``/``No``
  buttons via a timer rather than stubbing the static method, so a code
  change that skipped the prompt or mishandled a declined prompt is caught.

* **F-0022** -- ``HashingMixin._on_custom_crc`` must offload the CRC
  computation onto a :class:`GenericCallableWorker` and stream the document
  in bounded chunks (mmap for file-backed documents, the document API
  otherwise) instead of slurping the full payload onto the UI thread.

The document under test is the real :class:`intellicrack_hexcore.HexDocument`
opened over a real minimal 64-bit PE image, so the mixin exercises the exact
``repair_pe_checksum`` / ``verify_pe_checksum`` / ``read`` / ``length`` /
``file_path`` surface it uses in production. The expected checksum and CRC
values come from independent oracles (the hexcore PE checksum algorithm
applied to a known image, and :func:`zlib.crc32` for the CRC-32 parameter
set) rather than from the implementation's own captured output.
"""

from __future__ import annotations

import struct
import tracemalloc
import zlib
from typing import TYPE_CHECKING, Any, cast

import pytest
from intellicrack_hexcore import HexDocument
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QMessageBox, QPushButton, QWidget

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.ui.panels.hex_editor.base import compute_streaming_custom_crc
from intellicrack.ui.panels.hex_editor.hashing import HashingMixin
from intellicrack.ui.panels.hex_editor.widgets import CustomCrcDialog


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


# Standard zlib / PKZIP CRC-32 parameter set. Used both to configure the
# dialog and -- via zlib.crc32 -- as the independent correctness oracle.
_CRC32_WIDTH: int = 32
_CRC32_POLY: int = 0x04C11DB7
_CRC32_INIT: int = 0xFFFFFFFF
_CRC32_XOR_OUT: int = 0xFFFFFFFF


# The notify offset the mixin publishes is a fixed production constant
# (the canonical PE32 CheckSum field offset), independent of the real
# in-file offset the hexcore document repairs.
_NOTIFY_PE_CHECKSUM_OFFSET: int = 0x58
_NOTIFY_PE_CHECKSUM_LEN: int = 4

_REPAIR_SOURCE_ID: str = "hex-editor.hashing.repair_pe_checksum"


def _build_minimal_pe64() -> bytes:
    """Build a real, structurally valid minimal 64-bit PE image.

    The image is large enough for the hexcore PE checksum routine to locate
    and rewrite the optional-header ``CheckSum`` field. The ``CheckSum`` is
    initialised to zero so a repair produces a non-trivial, deterministic
    value derived from the image bytes.

    Returns:
        bytes: A 1024-byte PE image with a zeroed ``CheckSum`` field.
    """
    pe_offset = 0x40
    dos = bytearray(pe_offset)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_offset)

    pe_signature = b"PE\x00\x00"
    optional_header_size = 0xF0
    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,
        1,
        0,
        0,
        0,
        optional_header_size,
        0x0022,
    )

    optional_header = bytearray(optional_header_size)
    struct.pack_into("<H", optional_header, 0, 0x20B)
    struct.pack_into("<I", optional_header, 0x40, 0)

    body = bytes(dos) + pe_signature + coff_header + bytes(optional_header)
    return body + b"\x00" * (1024 - len(body))


def _open_pe_document() -> HexDocument:
    """Open the minimal PE image as a real ``intellicrack_hexcore`` document.

    Returns:
        HexDocument: A real document opened over the minimal PE image.
    """
    return HexDocument.open_bytes(_build_minimal_pe64())


class HashingHarness(QWidget, HashingMixin):
    """Concrete ``HashingMixin`` consumer used by the regression tests.

    Provides the attribute slots the mixin's type stubs declare so direct
    attribute access in ``HashingMixin`` resolves at runtime, while wiring a
    real hexcore document and a real :class:`HexDocumentState` so the repair
    and CRC flows exercise production collaborators.
    """

    def __init__(
        self,
        *,
        document: HexDocument,
        state_holder: HexDocumentState,
        file_path: Path | None = None,
    ) -> None:
        """Wire the mixin slots up to real collaborators.

        Args:
            document: Real ``intellicrack_hexcore.HexDocument`` exposing the
                hashing-mixin document surface.
            state_holder: Real :class:`HexDocumentState` whose
                ``notify_data_modified`` calls the test asserts on.
            file_path: Optional panel-side ``file_path`` attribute the mixin
                checks before falling back to ``document.file_path()``.
        """
        QWidget.__init__(self)
        self._document = document
        self.document = document
        self._hex_widget = None
        self._hash_algo_combo = None
        self._hash_result_label = None
        self._selection_start = -1
        self._selection_end = -1
        self._pe_checksum_status = None
        self.state_holder = state_holder
        self.file_path = file_path
        self._custom_crc_worker = None

    def repair_pe_checksum(self) -> None:
        """Invoke the mixin repair flow as a public test entry point.

        Delegates to :meth:`HashingMixin._on_repair_pe_checksum` so tests
        drive the full code path -- including the real confirmation dialog --
        through a public API without triggering ``reportPrivateUsage``.
        """
        self._on_repair_pe_checksum()

    def resolve_custom_crc_file_path(self) -> str | None:
        """Return the mixin's resolved CRC file path via a public entry point.

        Returns:
            str | None: Absolute path of an existing readable file, or
                ``None`` when the document has no usable file backing.
        """
        return self._resolve_custom_crc_file_path()


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


def _click_message_box_button(button: QMessageBox.StandardButton, *, recorder: dict[str, bool]) -> None:
    """Find the active modal ``QMessageBox`` and click ``button`` on it.

    Scans the top-level widgets for the confirmation dialog the repair flow
    opens and clicks the requested real button. Records whether a dialog was
    actually found so the test can assert the prompt really appeared.

    Args:
        button: The standard button to click (``Yes`` or ``No``).
        recorder: Mutable mapping; ``recorder["shown"]`` is set ``True`` when
            the modal message box is located.
    """
    for top in QApplication.topLevelWidgets():
        if isinstance(top, QMessageBox):
            recorder["shown"] = True
            target = top.button(button)
            if isinstance(target, QPushButton):
                target.click()
            return


@pytest.mark.usefixtures("qapp")
class TestRepairPeChecksumFiresNotify:
    """F-0003 -- ``_on_repair_pe_checksum`` confirmation, write, and notify."""

    @staticmethod
    def test_confirmed_repair_writes_real_checksum_and_fires_notify(qtbot: QtBot) -> None:
        """Confirming the real dialog repairs the PE checksum and notifies.

        Drives the real ``QMessageBox`` confirmation by clicking its real
        ``Yes`` button, then asserts: the hexcore document's ``CheckSum``
        field now holds the independently-known repaired value, the exact
        four bytes were written at the document's real checksum offset, and
        exactly one ``DATA_MODIFIED`` event was published carrying the
        production notify offset, width, and source identifier.

        Args:
            qtbot: pytest-qt bot fixture (ensures a live event loop).
        """
        del qtbot
        document = _open_pe_document()
        pre = document.verify_pe_checksum()
        expected_checksum = int(pre["calculated"])
        real_offset = int(pre["offset"])
        assert pre["valid"] is False
        assert int(pre["stored"]) != expected_checksum

        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="observer")
        harness = HashingHarness(document=document, state_holder=state)

        shown: dict[str, bool] = {"shown": False}
        QTimer.singleShot(50, lambda: _click_message_box_button(QMessageBox.StandardButton.Yes, recorder=shown))
        try:
            harness.repair_pe_checksum()
        finally:
            harness.deleteLater()

        assert shown["shown"], "the real confirmation dialog must have been shown"

        post = document.verify_pe_checksum()
        assert post["valid"] is True
        assert int(post["stored"]) == expected_checksum
        written = document.read(real_offset, 4)
        assert struct.unpack("<I", written)[0] == expected_checksum

        data_events = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.DATA_MODIFIED]
        assert len(data_events) == 1, f"expected exactly one DATA_MODIFIED event, got {recorder.events}"
        _, payload = data_events[0]
        assert payload["offset"] == _NOTIFY_PE_CHECKSUM_OFFSET
        assert payload["length"] == _NOTIFY_PE_CHECKSUM_LEN
        assert payload["source"] == _REPAIR_SOURCE_ID

    @staticmethod
    def test_declined_dialog_leaves_checksum_unwritten_and_silent(qtbot: QtBot) -> None:
        """Clicking ``No`` on the real dialog skips the write and the notify.

        Proves the repair is genuinely gated on the confirmation: the stored
        ``CheckSum`` stays at its original invalid value and no
        ``DATA_MODIFIED`` event is published. A monkeypatch that forced
        ``Yes`` could never catch a regression in the decline path.

        Args:
            qtbot: pytest-qt bot fixture (ensures a live event loop).
        """
        del qtbot
        document = _open_pe_document()
        pre = document.verify_pe_checksum()
        original_stored = int(pre["stored"])

        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="observer")
        harness = HashingHarness(document=document, state_holder=state)

        shown: dict[str, bool] = {"shown": False}
        QTimer.singleShot(50, lambda: _click_message_box_button(QMessageBox.StandardButton.No, recorder=shown))
        try:
            harness.repair_pe_checksum()
        finally:
            harness.deleteLater()

        assert shown["shown"], "the real confirmation dialog must have been shown"
        post = document.verify_pe_checksum()
        assert int(post["stored"]) == original_stored
        assert post["valid"] is False
        assert [evt for evt in recorder.events if evt[0] is HexDocumentEvent.DATA_MODIFIED] == []

    @staticmethod
    def test_loop_guard_suppresses_echo_for_same_source(qtbot: QtBot) -> None:
        """An observer registered with the repair source receives no echo.

        Registering the recorder with the same ``source_id`` the mixin passes
        to ``notify_data_modified`` proves the mixin used the documented
        identifier so the loop guard can suppress the self-echo.

        Args:
            qtbot: pytest-qt bot fixture (ensures a live event loop).
        """
        del qtbot
        document = _open_pe_document()
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id=_REPAIR_SOURCE_ID)
        harness = HashingHarness(document=document, state_holder=state)

        QTimer.singleShot(50, lambda: _click_message_box_button(QMessageBox.StandardButton.Yes, recorder={"shown": False}))
        try:
            harness.repair_pe_checksum()
        finally:
            harness.deleteLater()

        data_events = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.DATA_MODIFIED]
        assert data_events == [], (
            "the loop-guard filter must suppress the data_modified echo when the recorder registers with the "
            f"repair source_id, but received: {data_events!r}"
        )


def _configure_crc_dialog(dlg: CustomCrcDialog) -> None:
    """Pre-populate ``dlg`` with the standard CRC-32 parameter set.

    Uses ``getattr`` for the dialog's form fields so basedpyright does not
    emit ``reportPrivateUsage`` diagnostics for the single-underscore
    attributes.

    Args:
        dlg: Dialog whose form widgets are pre-set so the test does not depend
            on dialog defaults that may change.
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


def _build_crc_dialog(harness: HashingHarness, document: HexDocument) -> CustomCrcDialog:
    """Build a configured CRC dialog over a real hexcore document.

    Args:
        harness: Harness used as the dialog parent and CRC path resolver.
        document: Real hexcore document the worker will stream.

    Returns:
        CustomCrcDialog: Dialog pre-loaded with the CRC-32 parameter set.
    """
    dlg = CustomCrcDialog(
        file_path=harness.resolve_custom_crc_file_path(),
        document=document,
        length=int(document.length()),
        parent=harness,
        worker_parent=None,
    )
    _configure_crc_dialog(dlg)
    return dlg


def _emitted_crc(blocker: object) -> int:
    """Extract the integer CRC the dialog emitted via ``crc_computed``.

    Args:
        blocker: pytest-qt signal blocker whose ``args`` hold the payload.

    Returns:
        int: The emitted CRC value.
    """
    raw_args: object = getattr(blocker, "args", None)
    args_list: list[object] = list(cast("list[object]", raw_args)) if isinstance(raw_args, list) else []
    value: object = args_list[0] if args_list else None
    assert isinstance(value, int), f"worker emitted non-integer CRC: {value!r}"
    return value


def _drive_dialog_crc(harness: HashingHarness, document: HexDocument, qtbot: QtBot, *, timeout: int) -> int:
    """Run the dialog's offloaded CRC worker and return the emitted value.

    Args:
        harness: Harness used as the dialog parent and CRC path resolver.
        document: Real hexcore document the worker will stream.
        qtbot: pytest-qt bot used to block on the ``crc_computed`` signal.
        timeout: Maximum milliseconds to wait for the worker.

    Returns:
        int: The CRC value the worker emitted via ``crc_computed``.
    """
    dlg = _build_crc_dialog(harness, document)
    calculate_fn = getattr(dlg, "_calculate")
    with qtbot.waitSignal(dlg.crc_computed, timeout=timeout) as blocker:
        calculate_fn()
    return _emitted_crc(blocker)


def _measure_offloaded_crc_ui_growth(
    harness: HashingHarness,
    document: HexDocument,
    qtbot: QtBot,
    *,
    timeout: int,
) -> tuple[int, int]:
    """Run the offloaded CRC and return the emitted value and UI-thread growth.

    Captures a ``tracemalloc`` snapshot on the calling (UI) thread between
    dialog construction and worker dispatch, so the returned growth reflects
    only what the UI thread allocated while the worker streamed.

    Args:
        harness: Harness used as the dialog parent and CRC path resolver.
        document: Real hexcore document the worker will stream.
        qtbot: pytest-qt bot used to block on ``crc_computed``.
        timeout: Maximum milliseconds to wait for the worker.

    Returns:
        tuple[int, int]: ``(crc_value, ui_growth_bytes)``.
    """
    dlg = _build_crc_dialog(harness, document)
    calculate_fn = getattr(dlg, "_calculate")

    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()
    try:
        with qtbot.waitSignal(dlg.crc_computed, timeout=timeout) as blocker:
            calculate_fn()
            assert dlg.worker() is not None
            snapshot_during = tracemalloc.take_snapshot()
    finally:
        tracemalloc.stop()

    diff = snapshot_during.compare_to(snapshot_before, "lineno")
    ui_growth = sum(stat.size_diff for stat in diff if stat.size_diff > 0)
    return _emitted_crc(blocker), ui_growth


@pytest.mark.usefixtures("qapp")
class TestCustomCrcOffloaded:
    """F-0022 -- ``_on_custom_crc`` must offload + stream the CRC.

    Two concerns are validated independently: correctness (the streamed CRC
    equals the independent :func:`zlib.crc32` oracle on both the mmap and
    document paths) and resource bounds (the UI thread never copies the full
    document body while the worker streams a 50 MiB file).
    """

    @staticmethod
    def test_streamed_crc_matches_zlib_oracle_on_file_and_document(qtbot: QtBot, tmp_path: Path) -> None:
        """The offloaded worker returns the exact zlib CRC-32 of the bytes.

        Drives the real dialog worker over a real file-backed hexcore
        document, then cross-checks the emitted value against three
        independent computations: :func:`zlib.crc32` (the trusted oracle),
        the streaming helper's mmap path, and the streaming helper's
        document-chunk path. A byte-order, init, or truncation regression in
        any branch surfaces against the oracle.

        Args:
            qtbot: pytest-qt bot fixture used to wait on ``crc_computed``.
            tmp_path: Pytest temporary directory used to stage the document.
        """
        body: bytes = b"The quick brown fox jumps over the lazy dog" * 1024
        target: Path = tmp_path / "crc_correctness_target.bin"
        target.write_bytes(body)

        document = HexDocument.open(str(target))
        harness = HashingHarness(
            document=document,
            state_holder=HexDocumentState(),
            file_path=target,
        )

        try:
            crc_value = _drive_dialog_crc(harness, document, qtbot, timeout=60_000)
        finally:
            harness.deleteLater()

        zlib_oracle: int = zlib.crc32(body) & 0xFFFFFFFF
        assert crc_value == zlib_oracle, f"streamed CRC 0x{crc_value:08X} != zlib oracle 0x{zlib_oracle:08X}"

        helper_file: int = compute_streaming_custom_crc(
            str(target),
            None,
            _CRC32_WIDTH,
            _CRC32_POLY,
            _CRC32_INIT,
            ref_in=True,
            ref_out=True,
            xor_out=_CRC32_XOR_OUT,
        )
        assert helper_file == zlib_oracle

        helper_doc: int = compute_streaming_custom_crc(
            None,
            HexDocument.open_bytes(body),
            _CRC32_WIDTH,
            _CRC32_POLY,
            _CRC32_INIT,
            ref_in=True,
            ref_out=True,
            xor_out=_CRC32_XOR_OUT,
            chunk_size=8192,
        )
        assert helper_doc == zlib_oracle

    @staticmethod
    def test_empty_document_crc_matches_zlib_oracle(qtbot: QtBot, tmp_path: Path) -> None:
        """A zero-length document yields the zlib CRC-32 of the empty string.

        Exercises the boundary input (empty file) end to end through the real
        worker and asserts against the independent oracle ``zlib.crc32(b"")``.

        Args:
            qtbot: pytest-qt bot fixture used to wait on ``crc_computed``.
            tmp_path: Pytest temporary directory used to stage the document.
        """
        target: Path = tmp_path / "crc_empty_target.bin"
        target.write_bytes(b"")

        document = HexDocument.open(str(target))
        harness = HashingHarness(
            document=document,
            state_holder=HexDocumentState(),
            file_path=target,
        )
        try:
            crc_value = _drive_dialog_crc(harness, document, qtbot, timeout=30_000)
        finally:
            harness.deleteLater()

        assert crc_value == (zlib.crc32(b"") & 0xFFFFFFFF)

    @staticmethod
    def test_large_file_crc_stays_within_ui_memory_budget(qtbot: QtBot, tmp_path: Path) -> None:
        """Computing CRC on a 50 MiB file keeps UI allocations bounded.

        Measures peak Python allocations on the UI thread between dialog
        construction and worker dispatch via ``tracemalloc``. The budget
        accommodates the dialog widgets but rejects any code path that copies
        the 50 MiB body into Python-managed memory on the UI thread. The
        emitted CRC is still cross-checked against the ``zlib.crc32`` oracle so
        a correct-but-slurping implementation cannot pass on memory alone and
        a streaming-but-wrong implementation cannot pass on the value alone.

        Args:
            qtbot: pytest-qt bot fixture used to wait on ``crc_computed``.
            tmp_path: Pytest temporary directory used to stage the document.
        """
        size: int = 50 * 1024 * 1024
        pattern: bytes = bytes(range(256))
        repeats: int = size // len(pattern)
        body: bytes = pattern * repeats + pattern[: size - repeats * len(pattern)]
        assert len(body) == size
        target: Path = tmp_path / "crc_offload_target.bin"
        target.write_bytes(body)

        document = HexDocument.open(str(target))
        harness = HashingHarness(
            document=document,
            state_holder=HexDocumentState(),
            file_path=target,
        )
        try:
            crc_value, ui_growth = _measure_offloaded_crc_ui_growth(harness, document, qtbot, timeout=120_000)
        finally:
            harness.deleteLater()

        assert crc_value == (zlib.crc32(body) & 0xFFFFFFFF)

        ui_budget: int = 10 * 1024 * 1024
        assert ui_growth < ui_budget, (
            f"UI thread allocated {ui_growth / (1024 * 1024):.1f} MiB while the worker streamed a "
            f"{size / (1024 * 1024):.0f} MiB document; the budget is {ui_budget / (1024 * 1024):.0f} MiB. "
            "The dialog must offload + stream, not slurp."
        )
