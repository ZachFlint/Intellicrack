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
        self.read_args: list[tuple[int, int]] = []

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
        self.read_args.append((offset, length))
        return self._data[offset : offset + length]


class _CappedReadDocument:
    """Document whose ``read`` honours the requested offset but caps the length.

    Used to prove that ``read_document_for_scan`` requests the full document
    length: when the per-read length is capped below the document size, the
    returned content is a strict prefix only if the function asked for the whole
    length and the document refused to serve it all.
    """

    def __init__(self, data: bytes, cap: int) -> None:
        """Initialise with content and a per-read length cap.

        Args:
            data: Full document content.
            cap: Maximum number of bytes any single ``read`` may return.
        """
        self._data: bytes = data
        self._cap: int = cap
        self.requested_lengths: list[int] = []

    def length(self) -> int:
        """Return the document byte length.

        Returns:
            int: Number of bytes in the document.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        """Return a capped slice of the document data.

        Args:
            offset: Start offset.
            length: Number of bytes requested (served up to the cap).

        Returns:
            bytes: At most ``cap`` bytes starting at ``offset``.
        """
        self.requested_lengths.append(length)
        served = min(length, self._cap)
        return self._data[offset : offset + served]


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
        return True if w is None else w.wait(timeout_ms)

    def result_row_count(self) -> int:
        """Return the number of top-level rows in the results tree.

        Returns:
            int: Number of result rows currently displayed.
        """
        if self._sig_results_tree is None:
            return 0
        return self._sig_results_tree.topLevelItemCount()


class TestBytesPassthrough:
    """Verifies exact bytes fidelity through read_document_for_scan and the scan pipeline.

    The ``bytes`` branch in ``read_document_for_scan`` (``isinstance(raw, bytes): return raw``)
    must preserve every bit of the input without transformation, truncation, or padding.
    These tests confirm that bytes from a document's ``read()`` method are identical to what
    the caller receives - and that those bytes feed the signature scan engine unchanged.

    Unlike TestReadDocumentForScan, this class focuses exclusively on the bytes-type return
    path and verifies content integrity for adversarial inputs the other tests do not cover.
    """

    @staticmethod
    def test_bytes_passthrough() -> None:
        """``read_document_for_scan`` returns document bytes unchanged when read() yields bytes.

        This is the primary gate for the ``isinstance(raw, bytes): return raw`` branch.
        Three independently-computable properties are asserted:

        1. The returned object is bit-for-bit identical to what ``document.read`` returned.
        2. The type is exactly ``bytes`` (not a subtype or different container).
        3. The length is exactly the value returned by ``document.length()``.

        A regression in any one of these (truncation, type coercion, byte-level mutation)
        causes this test to fail.  The expected values are independently computed from the
        test's own payload, not derived from the implementation.

        Falsifiability proof:

        - If the function returned ``raw[:-1]`` (off-by-one), ``len(result) == 256`` fails.
        - If the function returned ``bytearray(raw)``, ``type(result) is bytes`` fails.
        - If the function applied any byte-level transform (XOR, mask, encode/decode),
          ``result == content`` fails because the full 256-value cycle (0x00..0xFF) contains
          every possible single-byte value; no transform can produce an identical output.
        - If the function ignored the document and returned a default value, the specific
          256-value sequence would not match.
        """
        content: bytes = bytes(range(256))
        doc = _StubDocument(content)

        result: bytes = read_document_for_scan(doc)

        assert type(result) is bytes, (
            f"Expected exactly bytes, got {type(result).__name__}; the bytes branch must not coerce to bytearray or any other type"
        )
        assert len(result) == 256, f"Expected 256 bytes (document.length()), got {len(result)}"
        assert result == content, (
            "Byte content was mutated; the bytes branch must return the bytes object unchanged. "
            f"First differing index: "
            f"{next((i for i in range(256) if result[i] != content[i]), 'none')}"
        )
        assert doc.read_call_count == 1, f"document.read must be called exactly once; called {doc.read_call_count} times"
        assert doc.read_args == [(0, 256)], (
            f"document.read must be called with offset=0, length=document.length()=256; got args={doc.read_args!r}"
        )

    @staticmethod
    def test_bytes_passthrough_high_value_octets() -> None:
        """Bytes with high-octet values (0x80-0xFF) are returned unchanged.

        Tests the ``isinstance(raw, bytes): return raw`` branch in
        ``read_document_for_scan`` with content where every byte value is
        above 0x7F.  A function that incorrectly decoded the bytes through
        a text codec (e.g. latin-1 round-trip) or masked the high bit would
        produce output that differs from the input; this assertion would
        catch it.
        """
        content: bytes = bytes(range(128, 256))
        doc = _StubDocument(content)

        result = read_document_for_scan(doc)

        assert isinstance(result, bytes), f"Expected bytes, got {type(result).__name__}"
        assert len(result) == 128, f"Expected 128 bytes, got {len(result)}"
        assert result == content, (
            "High-octet bytes were corrupted during passthrough; "
            f"first differing position: {next((i for i in range(len(result)) if result[i] != content[i]), None)}"
        )

    @staticmethod
    def test_bytes_passthrough_null_bytes_preserved() -> None:
        """Null bytes (0x00) embedded in content are preserved exactly.

        A function that treats null as a string terminator (C-style) would
        truncate the result at the first 0x00; asserting the full 256-byte
        result (0x00..0xFF) catches that corruption.
        """
        content: bytes = bytes(range(256))
        doc = _StubDocument(content)

        result = read_document_for_scan(doc)

        assert result == content, "Null bytes were truncated or corrupted during passthrough"
        assert result[0] == 0x00, "First byte (null) must be preserved"
        assert result[255] == 0xFF, "Last byte (0xFF) must be preserved"

    @staticmethod
    def test_bytes_passthrough_single_byte() -> None:
        """A single-byte document returns exactly one byte unchanged."""
        for value in (0x00, 0x41, 0x7F, 0xFF):
            content = bytes([value])
            doc = _StubDocument(content)
            result = read_document_for_scan(doc)
            assert result == content, f"Single byte 0x{value:02X} was not preserved; got {result!r}"
            assert len(result) == 1, f"Expected 1 byte for 0x{value:02X}, got {len(result)}"

    @staticmethod
    def test_bytes_passthrough_returns_bytes_not_bytearray() -> None:
        """When document.read returns bytes, read_document_for_scan returns bytes, not bytearray.

        The return type must be exactly ``bytes``, not ``bytearray`` or ``memoryview``,
        because downstream callers (execute_signature_scan) use bytes-specific operations.
        """
        content: bytes = b"\x4d\x5a\x90\x00"
        doc = _StubDocument(content)

        result = read_document_for_scan(doc)

        assert type(result) is bytes, f"Expected type bytes, got {type(result).__name__}"
        assert result == content

    @staticmethod
    def test_bytes_passthrough_no_copy_mutation_possible() -> None:
        """The returned bytes object is immutable and independent of the original document data.

        Bytes are immutable in Python, but this test ensures that the returned
        object has the correct value even when the logical source content contains
        a repeating pattern that could be misread as a shorter object.  A function
        that returned ``doc_data[:half]`` instead of ``doc_data`` would fail here.
        """
        half = b"\xab\xcd" * 64
        content: bytes = half + half
        doc = _StubDocument(content)

        result = read_document_for_scan(doc)

        assert len(result) == 256, f"Expected 256 bytes, got {len(result)}"
        assert result == content, "Repeated-pattern bytes were truncated to the first half"
        assert result[:128] == half
        assert result[128:] == half

    @staticmethod
    def test_bytes_pipeline_integrity_into_scan_engine(tmp_path: Path) -> None:
        """The exact bytes from a document flow unchanged into execute_signature_scan.

        Places a known 4-byte pattern at a specific offset deep in the document
        (offset 200) with a DIE database entry using ``"any"`` (full-scan) matching.
        If the bytes are truncated, shifted, or padded before reaching the scan
        engine, the pattern will not be found and the assertion fails.  The pattern
        is unique within the document, so a false positive from partial content is
        not possible.
        """
        marker: bytes = b"\xca\xfe\xba\xbe"
        filler: bytes = bytes(range(256))
        prefix: bytes = filler[:200]
        suffix: bytes = filler[:56]
        content: bytes = prefix + marker + suffix

        assert len(content) == 260
        assert content[200:204] == marker
        assert content.count(marker) == 1, "marker must appear exactly once for a clean assertion"

        doc = _StubDocument(content)
        db: list[dict[str, Any]] = [
            {"name": "CafeBabe", "type": "java", "version": "1.0", "patterns": [{"pattern": "cafebabe", "offset": "any"}]},
        ]
        db_path: Path = tmp_path / "scan.json"
        db_path.write_text(json.dumps(db), encoding="utf-8")

        results = execute_signature_scan_from_source(None, doc, "die", str(db_path))

        assert len(results) == 1, f"Expected exactly 1 match, got {len(results)}: {results!r}"
        match = results[0]
        assert match["name"] == "CafeBabe", f"Unexpected match name: {match['name']!r}"
        assert match["offset"] == 200, (
            f"Pattern found at offset {match['offset']}, expected 200; "
            "bytes may have been truncated or shifted before reaching the scan engine"
        )

    @staticmethod
    def test_bytes_pipeline_integrity_all_zeros_no_false_match(tmp_path: Path) -> None:
        """A document of all-zero bytes does not produce a match when no pattern is 0x00*.

        Verifies that bytes of value 0x00 are not silently promoted to some
        other value.  If read_document_for_scan inflated or corrupted zero bytes,
        the all-zero document would match patterns it should not.
        """
        content: bytes = bytes(256)
        doc = _StubDocument(content)
        db: list[dict[str, Any]] = [
            {"name": "NonZeroPattern", "type": "test", "version": "", "patterns": [{"pattern": "cafebabe", "offset": "any"}]},
        ]
        db_path: Path = tmp_path / "scan_zero.json"
        db_path.write_text(json.dumps(db), encoding="utf-8")

        results = execute_signature_scan_from_source(None, doc, "die", str(db_path))

        assert results == [], (
            f"Expected no matches on all-zero content, got: {results!r}; bytes may have been corrupted before reaching the scan engine"
        )

    @staticmethod
    def test_bytes_passthrough_preserves_exact_byte_order() -> None:
        """Byte order is preserved exactly, not reversed or shuffled.

        Uses a sequence where reversing or swapping adjacent bytes would produce
        a different scan match (MZ at offset 0 vs. ZM at offset 0).  The scan
        must find the forward-order MZ signature at offset 0.
        """
        content: bytes = b"\x4d\x5a" + bytes(62)
        doc = _StubDocument(content)

        result = read_document_for_scan(doc)

        assert result[:2] == b"\x4d\x5a", f"Byte order corrupted: expected MZ (4D 5A) at offset 0, got {result[:2].hex()!r}"
        assert result[2:] == bytes(62), "Trailing bytes corrupted during passthrough"


class TestReadDocumentForScan:
    """Unit tests for ``read_document_for_scan``."""

    @staticmethod
    def test_reads_full_document_with_correct_offset_and_length() -> None:
        """Reads the entire document via ``read(0, length())`` and returns its bytes.

        The document content is non-trivial (the full 0..255 byte range twice)
        and ``_StubDocument.read`` honours the requested ``offset``/``length``
        rather than echoing a fixed answer.  This pins three behaviours that a
        no-op or corrupted ``read_document_for_scan`` would violate: that
        ``read`` is invoked exactly once, that it is invoked with offset ``0``
        and the value returned by ``length()`` (the full size), and that the
        complete byte sequence is returned unchanged.
        """
        content = bytes(range(256)) * 2
        doc = _StubDocument(content)

        result = read_document_for_scan(doc)

        assert result == content
        assert isinstance(result, bytes)
        assert doc.read_call_count == 1
        assert doc.read_args == [(0, 512)]

    @staticmethod
    def test_partial_read_would_not_satisfy_full_content() -> None:
        """A document that under-reads yields fewer bytes, proving full length is requested.

        ``read_document_for_scan`` must request ``length()`` bytes; if it
        requested fewer, the returned content would be a truncated prefix.  This
        document caps every read at 4 bytes, so the function can only return the
        full content if it actually asks for the whole length and the document
        honours it.  Here the cap makes the result a strict prefix, which the
        assertion detects.
        """
        content = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
        doc = _CappedReadDocument(content, cap=4)

        result = read_document_for_scan(doc)

        assert result == content[:4]
        assert doc.requested_lengths == [len(content)]

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

        assert harness.worker() is not None, (
            "trigger_scan() must spawn a worker thread to offload the document read; "
            "no worker means the read was either skipped or performed synchronously on the UI thread."
        )
        assert doc.read_call_count == 0, "document.read must not run on the UI thread during trigger_scan()"

        finished = harness.wait_for_worker()
        assert finished, "Worker did not finish within the timeout"
        assert doc.read_call_count >= 1, "the worker thread must read the document after trigger_scan() returns"

        top_stats = snapshot_after.compare_to(snapshot_before, "lineno")
        peak_ui_alloc = sum(stat.size_diff for stat in top_stats if stat.size_diff > 0)

        assert doc.read_thread_ids, "no document.read calls were recorded; the worker never read the document"
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

        assert any(r.get("name") == "MZExecutable" for r in results), f"Expected MZExecutable match in results but got: {repr(results)}"

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
