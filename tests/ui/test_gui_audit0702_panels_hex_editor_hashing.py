# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for GUI audit finding H5 in the hex editor hashing mixin.

H5 -- ``_on_calculate_hash``, ``_on_hash_selection``, ``_on_verify_pe_checksum``
and ``_on_repair_pe_checksum`` used to call the hexcore document's hash and
PE-checksum methods directly on the Qt GUI thread. Hashing a large binary, or
scanning/repairing its PE checksum, therefore blocked the entire application
for the duration of the native call, with no busy indicator and no way to
cancel.

The fix routes every one of those document calls through a background
``GenericCallableWorker`` QThread (``HashingMixin._spawn_hex_worker``) and
only mutates the result label from the ``call_finished``/``call_error``
slots that Qt marshals back onto the GUI thread.

Each test below drives the real ``HashingMixin`` slot through a small
``QWidget`` harness backed by a document double whose hash/checksum methods
sleep for a fixed duration and record the identity of the OS thread that
executed them. This lets the tests assert, without mocking Qt or the mixin
itself:

* the GUI-thread call returns almost immediately even though the document
  method sleeps far longer than the return budget (proves the call is not
  synchronous on the calling thread);
* the placeholder text ("Computing...", "Verifying...", "Repairing...") is
  visible immediately after the call returns (proves a worker was
  dispatched before the slot returned);
* the document method actually executed on a different OS thread than the
  GUI thread (proves real offloading, not just an async-looking API);
* the result-formatting callback that mutates the label ran back on the GUI
  thread (proves the worker's ``pyqtSignal`` marshalled the result instead
  of the label being touched from the background thread).

Pre-fix, every one of these assertions is false: the call blocks for the
full sleep duration, the label never shows a placeholder, the document
method's recorded thread identity equals the GUI thread's, and the mixin
has no ``_hash_worker``/``_pe_checksum_worker`` attribute at all (so
``isinstance(worker, GenericCallableWorker)`` fails outright).
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QComboBox, QLabel, QMessageBox, QWidget

from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.hex_editor.hashing import HashingMixin


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_HASH_ALGO: Final[str] = "SHA256"
_HASH_VALUE: Final[str] = "deadbeef" * 8
_DOC_SLEEP_S: Final[float] = 0.5
_FAST_RETURN_BUDGET_S: Final[float] = 0.25
_WAIT_TIMEOUT_MS: Final[int] = 10_000
_SEL_START: Final[int] = 0x10
_SEL_END: Final[int] = 0x40
_CHECKSUM_VALUE: Final[int] = 0x1234


class _SlowHashDocument:
    """Document double whose hash/PE-checksum methods sleep, then record their thread.

    Each method sleeps ``_DOC_SLEEP_S`` before returning and records the
    identity of the OS thread that executed it (``threading.get_ident()``).
    A code path that still calls these methods synchronously on the GUI
    thread will (a) block the caller for the sleep duration and (b) record
    the GUI thread's own identity; a worker-backed code path does neither.
    """

    def __init__(self) -> None:
        """Initialise call counters and the per-method thread-identity log."""
        self.call_threads: dict[str, int] = {}
        self.compute_hash_calls: list[str] = []
        self.compute_hash_range_calls: list[tuple[int, int, str]] = []
        self.verify_calls: int = 0
        self.repair_calls: int = 0

    def compute_hash(self, algo: str) -> str:
        """Simulate a slow full-document hash computation.

        Args:
            algo: Hash algorithm name requested by the caller.

        Returns:
            str: The fixed test hash value.
        """
        time.sleep(_DOC_SLEEP_S)
        self.call_threads["compute_hash"] = threading.get_ident()
        self.compute_hash_calls.append(algo)
        return _HASH_VALUE

    def compute_hash_range(self, start: int, end: int, algo: str) -> str:
        """Simulate a slow ranged hash computation.

        Args:
            start: Inclusive start offset of the hashed range.
            end: Exclusive end offset of the hashed range.
            algo: Hash algorithm name requested by the caller.

        Returns:
            str: The fixed test hash value.
        """
        time.sleep(_DOC_SLEEP_S)
        self.call_threads["compute_hash_range"] = threading.get_ident()
        self.compute_hash_range_calls.append((start, end, algo))
        return _HASH_VALUE

    def verify_pe_checksum(self) -> dict[str, int | bool]:
        """Simulate a slow PE-checksum verification scan.

        Returns:
            dict[str, int | bool]: A self-consistent verification result
                with ``stored == calculated`` so ``valid`` is ``True``.
        """
        time.sleep(_DOC_SLEEP_S)
        self.call_threads["verify_pe_checksum"] = threading.get_ident()
        self.verify_calls += 1
        return {"stored": _CHECKSUM_VALUE, "calculated": _CHECKSUM_VALUE, "valid": True}

    def repair_pe_checksum(self) -> None:
        """Simulate a slow PE-checksum repair pass."""
        time.sleep(_DOC_SLEEP_S)
        self.call_threads["repair_pe_checksum"] = threading.get_ident()
        self.repair_calls += 1

    def length(self) -> int:
        """Return a fixed document length too small to contain a DOS header.

        Returns:
            int: Fixed length of 4 bytes.
        """
        return 4

    def read(self, offset: int, length: int) -> bytes:
        """Return ``length`` null bytes regardless of ``offset``.

        Args:
            offset: Ignored start offset.
            length: Number of null bytes to return.

        Returns:
            bytes: ``length`` zero bytes.
        """
        del offset
        return bytes(length)

    def file_path(self) -> str | None:
        """Report that this document has no on-disk backing.

        Returns:
            str | None: Always ``None``.
        """
        return None


class _HashingHarness(QWidget, HashingMixin):
    """Minimal real ``HashingMixin`` consumer used to drive the GUI slots.

    Overrides the main-thread result callbacks to additionally record the
    identity of the thread that executed them, so tests can assert those
    callbacks ran on the GUI thread rather than on the worker thread that
    computed the result. Exposes narrow public accessors so tests never
    touch the mixin's underscore-prefixed attributes directly.
    """

    def __init__(self, document: _SlowHashDocument) -> None:
        """Wire the mixin's required attribute slots to a slow document double.

        Args:
            document: Slow document double the hashing/PE-checksum slots
                will call into.
        """
        QWidget.__init__(self)
        self._document = document
        self.document = document
        self._hex_widget = None
        self._hash_algo_combo = QComboBox()
        self._hash_algo_combo.addItem(_HASH_ALGO)
        self._hash_result_label = QLabel()
        self._selection_start = -1
        self._selection_end = -1
        self._pe_checksum_status = QLabel()
        self.state_holder = None
        self.file_path = None
        self._custom_crc_worker = None
        self._hash_worker = None
        self._pe_checksum_worker = None
        self.main_thread_calls: dict[str, int] = {}

    def calculate_hash(self) -> None:
        """Invoke the mixin's calculate-hash slot as a public test entry point."""
        self._on_calculate_hash()

    def hash_selection(self, start: int, end: int) -> None:
        """Set a selection range and invoke the mixin's hash-selection slot.

        Args:
            start: Inclusive selection start offset.
            end: Exclusive selection end offset.
        """
        self._selection_start = start
        self._selection_end = end
        self._on_hash_selection()

    def verify_pe_checksum(self) -> None:
        """Invoke the mixin's verify-PE-checksum slot as a public test entry point."""
        self._on_verify_pe_checksum()

    def repair_pe_checksum(self) -> None:
        """Invoke the mixin's repair-PE-checksum slot as a public test entry point."""
        self._on_repair_pe_checksum()

    def hash_result_text(self) -> str:
        """Return the current hash-result label text.

        Returns:
            str: The label's text, or an empty string if unset.
        """
        return "" if self._hash_result_label is None else self._hash_result_label.text()

    def hash_worker(self) -> GenericCallableWorker | None:
        """Return the in-flight (or most recently started) hash worker.

        Returns:
            GenericCallableWorker | None: The worker instance, or ``None``
                if no hash operation has been started yet.
        """
        return self._hash_worker

    def pe_checksum_status_text(self) -> str:
        """Return the current PE-checksum status label text.

        Returns:
            str: The label's text, or an empty string if unset.
        """
        return "" if self._pe_checksum_status is None else self._pe_checksum_status.text()

    def pe_checksum_worker(self) -> GenericCallableWorker | None:
        """Return the in-flight (or most recently started) PE-checksum worker.

        Returns:
            GenericCallableWorker | None: The worker instance, or ``None``
                if no PE-checksum operation has been started yet.
        """
        return self._pe_checksum_worker

    def _on_hash_result_ready(self, result: object) -> None:
        """Record the calling thread, then apply the mixin's default handling.

        Args:
            result: Formatted hash display string produced by the worker.
        """
        self.main_thread_calls["hash_result_ready"] = threading.get_ident()
        super()._on_hash_result_ready(result)

    def _apply_pe_checksum_verification(self, info: object) -> None:
        """Record the calling thread, then apply the mixin's default handling.

        Args:
            info: Verification result produced by the worker.
        """
        self.main_thread_calls["apply_pe_checksum_verification"] = threading.get_ident()
        super()._apply_pe_checksum_verification(info)

    def _on_pe_checksum_repaired(self, result: object) -> None:
        """Record the calling thread, then apply the mixin's default handling.

        Args:
            result: The (unused) return value of the repair worker.
        """
        self.main_thread_calls["pe_checksum_repaired"] = threading.get_ident()
        super()._on_pe_checksum_repaired(result)

    def _apply_post_repair_verification(self, info: object) -> None:
        """Record the calling thread, then apply the mixin's default handling.

        Args:
            info: Post-repair verification result produced by the worker.
        """
        self.main_thread_calls["apply_post_repair_verification"] = threading.get_ident()
        super()._apply_post_repair_verification(info)


def _answer_yes(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
    """Return ``Yes`` for any ``QMessageBox.question`` call, ignoring arguments.

    Args:
        *_args: Ignored positional arguments forwarded by ``QMessageBox.question``.
        **_kwargs: Ignored keyword arguments forwarded by ``QMessageBox.question``.

    Returns:
        QMessageBox.StandardButton: Always ``QMessageBox.StandardButton.Yes``.
    """
    return QMessageBox.StandardButton.Yes


def test_h5_calculate_hash_offloads_to_worker_thread(qtbot: QtBot) -> None:
    """H5: ``_on_calculate_hash`` must run ``document.compute_hash`` off the GUI thread.

    Drives the real slot with a document whose ``compute_hash`` sleeps for
    ``_DOC_SLEEP_S``. Pre-fix, the slot called ``document.compute_hash``
    inline: this call would then block for the full sleep duration, the
    label would never show a "Computing..." placeholder, the document would
    record the GUI thread's own identity as the caller, and there would be
    no ``_hash_worker`` attribute to type-check as a
    ``GenericCallableWorker``. Each of those four checks fails pre-fix and
    passes post-fix.

    Args:
        qtbot: pytest-qt bot fixture used to wait on the worker's completion
            signal.
    """
    gui_thread = threading.get_ident()
    document = _SlowHashDocument()
    harness = _HashingHarness(document)
    try:
        started = time.perf_counter()
        harness.calculate_hash()
        elapsed = time.perf_counter() - started

        assert elapsed < _FAST_RETURN_BUDGET_S, (
            f"_on_calculate_hash blocked the calling thread for {elapsed:.3f}s "
            f"(document.compute_hash sleeps {_DOC_SLEEP_S}s); a call that is still "
            "synchronous on the GUI thread would take at least that long."
        )
        assert harness.hash_result_text() == f"{_HASH_ALGO}: Computing...", (
            f"expected an immediate 'Computing...' placeholder, got {harness.hash_result_text()!r}"
        )

        worker = harness.hash_worker()
        assert isinstance(worker, GenericCallableWorker), "_on_calculate_hash did not dispatch a GenericCallableWorker"

        with qtbot.waitSignal(worker.call_finished, timeout=_WAIT_TIMEOUT_MS):
            pass

        assert harness.hash_result_text() == f"{_HASH_ALGO}: {_HASH_VALUE}"
        assert document.compute_hash_calls == [_HASH_ALGO]

        bg_thread = document.call_threads.get("compute_hash")
        assert bg_thread is not None
        assert bg_thread != gui_thread, "document.compute_hash executed on the GUI thread instead of a background worker"

        callback_thread = harness.main_thread_calls.get("hash_result_ready")
        assert callback_thread == gui_thread, "the callback that mutates the result label did not run back on the GUI thread"
    finally:
        harness.deleteLater()


def test_h5_hash_selection_offloads_to_worker_thread(qtbot: QtBot) -> None:
    """H5: ``_on_hash_selection`` must run ``document.compute_hash_range`` off the GUI thread.

    Mirrors ``test_h5_calculate_hash_offloads_to_worker_thread`` for the
    selection-hashing slot. Pre-fix this slot called
    ``document.compute_hash_range`` inline, so it would block for the full
    sleep duration and the recorded calling thread would be the GUI thread.

    Args:
        qtbot: pytest-qt bot fixture used to wait on the worker's completion
            signal.
    """
    gui_thread = threading.get_ident()
    document = _SlowHashDocument()
    harness = _HashingHarness(document)
    try:
        started = time.perf_counter()
        harness.hash_selection(_SEL_START, _SEL_END)
        elapsed = time.perf_counter() - started

        assert elapsed < _FAST_RETURN_BUDGET_S, (
            f"_on_hash_selection blocked the calling thread for {elapsed:.3f}s (document.compute_hash_range sleeps {_DOC_SLEEP_S}s)."
        )
        expected_placeholder = f"{_HASH_ALGO} (0x{_SEL_START:X}-0x{_SEL_END:X}): Computing..."
        assert harness.hash_result_text() == expected_placeholder

        worker = harness.hash_worker()
        assert isinstance(worker, GenericCallableWorker), "_on_hash_selection did not dispatch a GenericCallableWorker"

        with qtbot.waitSignal(worker.call_finished, timeout=_WAIT_TIMEOUT_MS):
            pass

        expected_final = f"{_HASH_ALGO} (0x{_SEL_START:X}-0x{_SEL_END:X}): {_HASH_VALUE}"
        assert harness.hash_result_text() == expected_final
        assert document.compute_hash_range_calls == [(_SEL_START, _SEL_END, _HASH_ALGO)]

        bg_thread = document.call_threads.get("compute_hash_range")
        assert bg_thread is not None
        assert bg_thread != gui_thread, "document.compute_hash_range executed on the GUI thread instead of a background worker"

        callback_thread = harness.main_thread_calls.get("hash_result_ready")
        assert callback_thread == gui_thread, "the callback that mutates the result label did not run back on the GUI thread"
    finally:
        harness.deleteLater()


def test_h5_verify_pe_checksum_offloads_to_worker_thread(qtbot: QtBot) -> None:
    """H5: ``_on_verify_pe_checksum`` must run ``document.verify_pe_checksum`` off the GUI thread.

    Pre-fix this slot called ``document.verify_pe_checksum`` inline, so
    the call would block the caller for the sleep duration, the status
    label would never show a "Verifying..." placeholder, and the recorded
    calling thread would equal the GUI thread's identity.

    Args:
        qtbot: pytest-qt bot fixture used to wait on the worker's completion
            signal.
    """
    gui_thread = threading.get_ident()
    document = _SlowHashDocument()
    harness = _HashingHarness(document)
    try:
        started = time.perf_counter()
        harness.verify_pe_checksum()
        elapsed = time.perf_counter() - started

        assert elapsed < _FAST_RETURN_BUDGET_S, (
            f"_on_verify_pe_checksum blocked the calling thread for {elapsed:.3f}s (document.verify_pe_checksum sleeps {_DOC_SLEEP_S}s)."
        )
        assert harness.pe_checksum_status_text() == "Verifying..."

        worker = harness.pe_checksum_worker()
        assert isinstance(worker, GenericCallableWorker), "_on_verify_pe_checksum did not dispatch a GenericCallableWorker"

        with qtbot.waitSignal(worker.call_finished, timeout=_WAIT_TIMEOUT_MS):
            pass

        assert harness.pe_checksum_status_text() == f"Valid: 0x{_CHECKSUM_VALUE:08X}"
        assert document.verify_calls == 1

        bg_thread = document.call_threads.get("verify_pe_checksum")
        assert bg_thread is not None
        assert bg_thread != gui_thread, "document.verify_pe_checksum executed on the GUI thread instead of a background worker"

        callback_thread = harness.main_thread_calls.get("apply_pe_checksum_verification")
        assert callback_thread == gui_thread, "the callback that mutates the status label did not run back on the GUI thread"
    finally:
        harness.deleteLater()


def test_h5_repair_pe_checksum_offloads_to_worker_thread(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H5: ``_on_repair_pe_checksum`` must run repair and post-repair verify off the GUI thread.

    Pre-fix this slot called ``document.repair_pe_checksum`` and the
    subsequent ``document.verify_pe_checksum`` inline, blocking the caller
    for two sleep durations combined and recording the GUI thread's own
    identity for both calls. The fix chains two background workers
    (repair, then verify) and only ever touches the status label from
    their ``call_finished`` callbacks.

    Args:
        qtbot: pytest-qt bot fixture used to wait on each worker's
            completion signal.
        monkeypatch: pytest fixture used to force the confirmation dialog
            to answer "Yes" without blocking on real user input.
    """
    monkeypatch.setattr(QMessageBox, "question", _answer_yes)

    gui_thread = threading.get_ident()
    document = _SlowHashDocument()
    harness = _HashingHarness(document)
    try:
        started = time.perf_counter()
        harness.repair_pe_checksum()
        elapsed = time.perf_counter() - started

        assert elapsed < _FAST_RETURN_BUDGET_S, (
            f"_on_repair_pe_checksum blocked the calling thread for {elapsed:.3f}s (document.repair_pe_checksum sleeps {_DOC_SLEEP_S}s)."
        )
        assert harness.pe_checksum_status_text() == "Repairing..."

        repair_worker = harness.pe_checksum_worker()
        assert isinstance(repair_worker, GenericCallableWorker), "_on_repair_pe_checksum did not dispatch a GenericCallableWorker"

        with qtbot.waitSignal(repair_worker.call_finished, timeout=_WAIT_TIMEOUT_MS):
            pass

        verify_worker = harness.pe_checksum_worker()
        assert isinstance(verify_worker, GenericCallableWorker), (
            "the post-repair verification did not dispatch a second GenericCallableWorker"
        )
        assert verify_worker is not repair_worker, "the post-repair verification reused the repair worker instead of starting a new one"

        with qtbot.waitSignal(verify_worker.call_finished, timeout=_WAIT_TIMEOUT_MS):
            pass

        assert harness.pe_checksum_status_text() == f"Repaired: 0x{_CHECKSUM_VALUE:08X}"
        assert document.repair_calls == 1
        assert document.verify_calls == 1

        repair_thread = document.call_threads.get("repair_pe_checksum")
        verify_thread = document.call_threads.get("verify_pe_checksum")
        assert repair_thread is not None
        assert verify_thread is not None
        assert repair_thread != gui_thread, "document.repair_pe_checksum executed on the GUI thread instead of a background worker"
        assert verify_thread != gui_thread, "the post-repair document.verify_pe_checksum executed on the GUI thread"

        assert harness.main_thread_calls.get("pe_checksum_repaired") == gui_thread, (
            "the repair-completion callback did not run back on the GUI thread"
        )
        assert harness.main_thread_calls.get("apply_post_repair_verification") == gui_thread, (
            "the post-repair-verification callback did not run back on the GUI thread"
        )
    finally:
        harness.deleteLater()
