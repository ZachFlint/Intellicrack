# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for audit4 C8 - F-0023: signature scan read offloaded from the UI thread.

Validates that:

* ``_on_scan_signatures`` does not materialise the full document on the UI
  thread; tracemalloc confirms the UI-thread allocation budget stays small
  even for a 50 MiB document.
* The worker callable receives the correct bytes derived from the document.
* ``execute_signature_scan`` is invoked with the correct bytes when the
  scan runs end-to-end via a document-backed source.
"""

from __future__ import annotations

import json
import threading
import tracemalloc
from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtWidgets import QComboBox, QLabel, QTreeWidget, QWidget

from intellicrack.ui.panels.hex_editor.signatures import (
    SignaturesMixin,
    execute_signature_scan,
    execute_signature_scan_from_source,
    read_document_for_scan,
    read_file_for_scan,
)


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtCore import QCoreApplication

    from intellicrack.ui.panels.async_bridge import GenericCallableWorker


_LARGE_DOC_SIZE: Final[int] = 50 * 1024 * 1024
_UI_ALLOC_BUDGET_BYTES: Final[int] = 1 * 1024 * 1024
_WORKER_TIMEOUT_MS: Final[int] = 10_000
_MZ_PATTERN: Final[bytes] = b"MZ"


class _StubDocument:
    """In-memory document stub that records whether ``read`` was called and from which thread."""

    def __init__(self, data: bytes) -> None:
        """Initialise with the given byte content.

        Args:
            data: Bytes the document should return from ``read``.
        """
        self._data: bytes = data
        self.read_call_count: int = 0
        self.read_thread_ids: list[int] = []

    def length(self) -> int:
        """Return the document byte length.

        Returns:
            int: Number of bytes in the document.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        """Return a slice of the document data.

        Args:
            offset: Start offset.
            length: Number of bytes to return.

        Returns:
            bytes: Slice of the document data.
        """
        self.read_call_count += 1
        self.read_thread_ids.append(threading.get_ident())
        return self._data[offset : offset + length]


class _MixinHarness(SignaturesMixin, QWidget):
    """Concrete harness that wires SignaturesMixin into a real QWidget.

    All interaction with the mixin is exposed via public accessor methods to
    avoid protected-member access from outside the class.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialise the harness with null mixin state.

        Args:
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self.document: Any | None = None
        self.file_path: Path | None = None
        self._sig_db_type_combo: QComboBox | None = QComboBox()
        self._sig_db_path_label: QLabel | None = QLabel()
        self._sig_results_tree: QTreeWidget | None = QTreeWidget()
        self._sig_worker: GenericCallableWorker | None = None
        self._sig_db_path: str = ""

    def set_document(self, doc: object) -> None:
        """Assign a document to the mixin.

        Args:
            doc: Document object to assign.
        """
        self.document = doc

    def set_file_path(self, path: Path | None) -> None:
        """Assign a file path to the mixin.

        Args:
            path: File path to assign, or ``None`` to clear.
        """
        self.file_path = path

    def set_sig_db_path(self, path: str) -> None:
        """Set the signature database path.

        Args:
            path: Path to the signature database file.
        """
        self._sig_db_path = path

    def trigger_scan(self) -> None:
        """Invoke the protected ``_on_scan_signatures`` slot."""
        self._on_scan_signatures()

    def worker(self) -> GenericCallableWorker | None:
        """Return the current worker instance.

        Returns:
            GenericCallableWorker | None: The worker, or ``None`` if not started.
        """
        return self._sig_worker

    def wait_for_worker(self, timeout_ms: int = _WORKER_TIMEOUT_MS) -> bool:
        """Block until the scan worker completes, pumping the Qt event loop.

        Args:
            timeout_ms: Maximum wait time in milliseconds.

        Returns:
            bool: ``True`` if the worker finished within the timeout.
        """
        w = self._sig_worker
        if w is None:
            return True
        return w.wait(timeout_ms)

    def result_row_count(self) -> int:
        """Return the number of top-level rows in the results tree.

        Returns:
            int: Number of result rows currently displayed.
        """
        if self._sig_results_tree is None:
            return 0
        return self._sig_results_tree.topLevelItemCount()


class TestReadDocumentForScan:
    """Unit tests for ``read_document_for_scan``."""

    @staticmethod
    def test_bytes_passthrough() -> None:
        """Returns bytes unchanged when document.read returns bytes."""
        doc = _StubDocument(b"hello world")
        result = read_document_for_scan(doc)
        assert result == b"hello world"

    @staticmethod
    def test_bytearray_converted() -> None:
        """Converts bytearray from document.read into bytes."""

        class _BytearrayDoc:
            def length(self) -> int:
                """Return document length.

                Returns:
                    int: Document length.
                """
                return 5

            def read(self, offset: int, length: int) -> bytearray:
                """Return document data as bytearray.

                Args:
                    offset: Start offset.
                    length: Number of bytes.

                Returns:
                    bytearray: Data slice.
                """
                return bytearray(b"abcde")[offset : offset + length]

        result = read_document_for_scan(_BytearrayDoc())
        assert result == b"abcde"
        assert isinstance(result, bytes)

    @staticmethod
    def test_list_int_converted() -> None:
        """Converts list[int] from document.read into bytes."""

        class _ListDoc:
            def length(self) -> int:
                """Return document length.

                Returns:
                    int: Document length.
                """
                return 3

            def read(self, offset: int, length: int) -> list[int]:
                """Return document data as list of ints.

                Args:
                    offset: Start offset.
                    length: Number of bytes.

                Returns:
                    list[int]: Data as integers.
                """
                return [0x41, 0x42, 0x43][offset : offset + length]

        result = read_document_for_scan(_ListDoc())
        assert result == b"ABC"

    @staticmethod
    def test_missing_api_raises_type_error() -> None:
        """Raises TypeError when the object has no length/read methods."""
        with pytest.raises(TypeError, match="length\\(\\) and read\\(\\)"):
            read_document_for_scan(object())


class TestReadFileForScan:
    """Unit tests for ``read_file_for_scan``."""

    @staticmethod
    def test_reads_file_content(tmp_path: Path) -> None:
        """Returns exact bytes written to the file.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        target = tmp_path / "sample.bin"
        payload = b"\x4d\x5a" + bytes(range(128))
        target.write_bytes(payload)
        result = read_file_for_scan(target)
        assert result == payload

    @staticmethod
    def test_empty_file_returns_empty_bytes(tmp_path: Path) -> None:
        """Returns empty bytes for a zero-length file.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        empty = tmp_path / "empty.bin"
        empty.write_bytes(b"")
        result = read_file_for_scan(empty)
        assert result == b""


class TestExecuteSigScanFromSource:
    """Unit tests for ``execute_signature_scan_from_source``."""

    @staticmethod
    def _make_die_db(tmp_path: Path) -> Path:
        """Write a minimal DIE JSON database that matches an MZ header.

        Args:
            tmp_path: Pytest temporary directory fixture.

        Returns:
            Path: Path to the written database file.
        """
        db: list[dict[str, Any]] = [
            {"name": "MZ", "type": "exe", "version": "1.0", "patterns": ["4d5a"]},
        ]
        db_path = tmp_path / "test.json"
        db_path.write_text(json.dumps(db), encoding="utf-8")
        return db_path

    @staticmethod
    def test_file_path_used_when_file_exists(tmp_path: Path) -> None:
        """Uses ``file_path`` when the file exists, not document.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        payload = _MZ_PATTERN + bytes(126)
        bin_path = tmp_path / "target.bin"
        bin_path.write_bytes(payload)

        doc = _StubDocument(b"different bytes - should not be read")
        db: list[dict[str, Any]] = [
            {"name": "MZ", "type": "exe", "version": "", "patterns": ["4d5a"]},
        ]
        db_path = tmp_path / "test.json"
        db_path.write_text(json.dumps(db), encoding="utf-8")

        results = execute_signature_scan_from_source(str(bin_path), doc, "die", str(db_path))
        assert doc.read_call_count == 0, "document.read must NOT be called when file_path resolves"
        assert len(results) >= 1

    @staticmethod
    def test_document_fallback_when_no_file(tmp_path: Path) -> None:
        """Falls back to document when ``file_path`` is ``None``.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        payload = _MZ_PATTERN + bytes(126)
        doc = _StubDocument(payload)
        db: list[dict[str, Any]] = [
            {"name": "MZ", "type": "exe", "version": "", "patterns": ["4d5a"]},
        ]
        db_path = tmp_path / "test.json"
        db_path.write_text(json.dumps(db), encoding="utf-8")

        results = execute_signature_scan_from_source(None, doc, "die", str(db_path))
        assert doc.read_call_count >= 1, "document.read must be called when file_path is None"
        assert len(results) >= 1

    @staticmethod
    def test_neither_raises_value_error() -> None:
        """Raises ValueError when both file_path and document are absent."""
        with pytest.raises(ValueError, match="No file path and no document"):
            execute_signature_scan_from_source(None, None, "die", "/fake/db.json")

    @staticmethod
    def test_missing_file_and_no_doc_raises(tmp_path: Path) -> None:
        """Raises ValueError when file_path does not exist and document is None.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        missing = tmp_path / "nonexistent.bin"
        with pytest.raises(ValueError, match="File not found"):
            execute_signature_scan_from_source(str(missing), None, "die", "/fake/db.json")


class TestUIThreadAllocationBudget:
    """Verifies that ``_on_scan_signatures`` does not read the document on the UI thread."""

    @staticmethod
    def test_ui_thread_does_not_materialise_large_document(
        qapp: QCoreApplication,
        tmp_path: Path,
    ) -> None:
        """UI-thread allocation stays below budget for a 50 MiB document.

        Uses ``tracemalloc`` to measure Python heap allocations on the UI
        (main) thread while ``_on_scan_signatures`` is called.  The test
        asserts that the peak allocation attributable to ``_on_scan_signatures``
        remains below ``_UI_ALLOC_BUDGET_BYTES`` (1 MiB), confirming that the
        50 MiB document body is not copied into Python heap on the UI thread.
        Thread identity of each ``document.read`` call is also verified to
        confirm reads only happen off the main thread.

        Args:
            qapp: QApplication instance required by Qt widgets.
            tmp_path: Pytest temporary directory fixture.
        """
        _ = qapp
        main_thread_id = threading.get_ident()

        large_data = bytes(range(256)) * (_LARGE_DOC_SIZE // 256)
        doc = _StubDocument(large_data)

        db: list[dict[str, Any]] = []
        db_path = tmp_path / "empty.json"
        db_path.write_text(json.dumps(db), encoding="utf-8")

        harness = _MixinHarness()
        harness.set_document(doc)
        harness.set_sig_db_path(str(db_path))

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()
        harness.trigger_scan()
        snapshot_after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        if harness.worker() is not None:
            harness.wait_for_worker()

        top_stats = snapshot_after.compare_to(snapshot_before, "lineno")
        peak_ui_alloc = sum(stat.size_diff for stat in top_stats if stat.size_diff > 0)

        for caller_thread_id in doc.read_thread_ids:
            assert caller_thread_id != main_thread_id, (
                "_StubDocument.read was called from the main (UI) thread; "
                "the document read must happen on the worker thread only. "
                f"Main thread id={main_thread_id}, caller thread id={caller_thread_id}"
            )
        assert peak_ui_alloc < _UI_ALLOC_BUDGET_BYTES, (
            f"UI-thread allocated {peak_ui_alloc:,} bytes during _on_scan_signatures; "
            f"budget is {_UI_ALLOC_BUDGET_BYTES:,} bytes. "
            "The 50 MiB document body must not be read on the UI thread."
        )


class TestWorkerReceivesCorrectBytes:
    """Verifies the worker callable receives the document bytes correctly."""

    @staticmethod
    def test_scan_from_source_invokes_execute_scan(tmp_path: Path) -> None:
        """``execute_signature_scan_from_source`` passes correct bytes to ``execute_signature_scan``.

        Creates a document with known content including the MZ header, runs
        ``execute_signature_scan_from_source`` directly (simulating the worker
        thread), and asserts that the returned results contain the expected
        MZ match.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        payload = _MZ_PATTERN + bytes(126)
        doc = _StubDocument(payload)

        db: list[dict[str, Any]] = [
            {"name": "MZExecutable", "type": "win32", "version": "1.0", "patterns": ["4d5a"]},
        ]
        db_path = tmp_path / "die.json"
        db_path.write_text(json.dumps(db), encoding="utf-8")

        results = execute_signature_scan_from_source(None, doc, "die", str(db_path))

        assert any(r.get("name") == "MZExecutable" for r in results), "Expected MZExecutable match in results but got: " + repr(results)

    @staticmethod
    def test_execute_signature_scan_direct(tmp_path: Path) -> None:
        """``execute_signature_scan`` returns correct matches for known bytes.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        payload = _MZ_PATTERN + bytes(126)
        db: list[dict[str, Any]] = [
            {"name": "MZHeader", "type": "win32", "version": "", "patterns": ["4d5a"]},
        ]
        db_path = tmp_path / "die.json"
        db_path.write_text(json.dumps(db), encoding="utf-8")

        results = execute_signature_scan(payload, "die", str(db_path))
        assert any(r.get("name") == "MZHeader" for r in results)

    @staticmethod
    def test_worker_thread_reads_document(
        qapp: QCoreApplication,
        tmp_path: Path,
    ) -> None:
        """The worker thread calls document.read, not the UI thread.

        Starts the scan via the mixin harness, waits for completion, and
        asserts that the stub document's ``read_call_count`` is positive only
        after the worker has run.

        Args:
            qapp: QApplication instance required by Qt widgets.
            tmp_path: Pytest temporary directory fixture.
        """
        _ = qapp
        payload = _MZ_PATTERN + bytes(62)
        doc = _StubDocument(payload)

        db: list[dict[str, Any]] = [
            {"name": "MZScan", "type": "win32", "version": "", "patterns": ["4d5a"]},
        ]
        db_path = tmp_path / "die.json"
        db_path.write_text(json.dumps(db), encoding="utf-8")

        harness = _MixinHarness()
        harness.set_document(doc)
        harness.set_sig_db_path(str(db_path))

        assert doc.read_call_count == 0, "read_call_count must be 0 before scan"
        harness.trigger_scan()
        assert doc.read_call_count == 0, "document.read must NOT have been called on the UI thread by trigger_scan()"

        finished = harness.wait_for_worker()
        assert finished, "Worker did not finish within timeout"

        assert doc.read_call_count >= 1, "document.read must have been called by the worker thread after completion"
