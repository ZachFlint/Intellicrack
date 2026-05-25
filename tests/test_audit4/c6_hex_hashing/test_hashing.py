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

All three test cases would fail against the pre-audit code: the
``notify_data_modified`` recorder would stay empty for the repair
test, the ``tracemalloc`` budget for the offload test would explode
because the UI thread used to call ``document.read(0, 50 MiB)``, and
the streaming CRC value would be unobservable because the dialog had
no signal to expose it.
"""

from __future__ import annotations

import struct
import tracemalloc
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QMessageBox, QWidget

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.ui.panels.hex_editor._base import (
    compute_custom_crc,
    compute_streaming_custom_crc,
)
from intellicrack.ui.panels.hex_editor._hashing import HashingMixin
from intellicrack.ui.panels.hex_editor._widgets import CustomCrcDialog


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


# CRC-32 parameters that match the bit-serial implementation in
# intellicrack.ui.panels.hex_editor._base.compute_custom_crc when the
# input is reflected (matches the legacy zlib CRC-32 surface).
_CRC32_WIDTH: int = 32
_CRC32_POLY: int = 0x04C11DB7
_CRC32_INIT: int = 0xFFFFFFFF
_CRC32_XOR_OUT: int = 0xFFFFFFFF


_PE_CHECKSUM_OFFSET: int = 0x58


class StubPeDocument:
    """In-memory document exposing the methods the hashing mixin uses.

    Mirrors the surface that ``HexDocumentFull``-style documents
    expose so the hashing mixin can drive ``repair_pe_checksum``,
    ``verify_pe_checksum``, ``length``, ``read`` and ``file_path``
    without needing the real Rust hexcore module loaded.
    """

    def __init__(self, data: bytes, *, file_path: str | None = None) -> None:
        """Capture the initial bytes and optional backing path.

        Args:
            data: Initial document content.
            file_path: Optional path returned by ``file_path()`` so the
                streaming CRC source can prefer mmap.
        """
        self._data: bytearray = bytearray(data)
        self._file_path: str | None = file_path
        self.repair_calls: int = 0
        self.verify_calls: int = 0

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
        """Overwrite the four checksum bytes with a fixed test value.

        The exact value is irrelevant for the regression test; what
        matters is that the document mutates so the mixin must publish
        a :meth:`HexDocumentState.notify_data_modified` event.
        """
        self.repair_calls += 1
        struct.pack_into("<I", self._data, _PE_CHECKSUM_OFFSET, 0xC0FFEE42)

    def verify_pe_checksum(self) -> dict[str, Any]:
        """Return verification metadata for the current checksum field.

        Returns:
            dict[str, Any]: Mapping with ``stored``, ``calculated``,
                ``offset`` and ``valid`` keys, matching the contract
                used by the hexcore document.
        """
        self.verify_calls += 1
        stored = struct.unpack_from("<I", self._data, _PE_CHECKSUM_OFFSET)[0]
        calculated = 0xC0FFEE42
        return {
            "stored": stored,
            "calculated": calculated,
            "offset": _PE_CHECKSUM_OFFSET,
            "valid": stored == calculated,
        }


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

    def fake_question(
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

    monkeypatch.setattr(QMessageBox, "question", fake_question)


@pytest.mark.usefixtures("qapp", "message_box_yes")
class TestRepairPeChecksumFiresNotify:
    """F-0003 -- ``_on_repair_pe_checksum`` must call ``notify_data_modified``."""

    @staticmethod
    def test_insert_hash_fires_notify() -> None:
        """Driving the repair action emits one ``DATA_MODIFIED`` event.

        The recorded event must reference the real PE ``CheckSum``
        offset, the four-byte field width and the audit-defined
        source identifier so observers can apply loop-guard filters
        and route the change correctly.
        """
        document = StubPeDocument(b"\x00" * 256)
        state = HexDocumentState()

        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")
        harness = HashingHarness(document=document, state_holder=state)
        try:
            harness.repair_pe_checksum()
        finally:
            harness.deleteLater()

        assert document.repair_calls == 1
        data_events = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.DATA_MODIFIED]
        assert len(data_events) == 1, f"expected exactly one DATA_MODIFIED event, got {recorder.events}"
        _, payload = data_events[0]
        assert payload["offset"] == _PE_CHECKSUM_OFFSET
        assert payload["length"] == 4

    @staticmethod
    def test_repair_uses_audit_defined_source_identifier() -> None:
        """The ``source`` argument lets the loop guard suppress the echo.

        Registering the recorder with the same ``source_id`` the mixin
        passes to ``notify_data_modified`` proves the mixin used the
        documented identifier instead of an unrelated string.
        """
        document = StubPeDocument(b"\x00" * 256)
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
