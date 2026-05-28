# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""JSON-Lines tail reader for the Log Viewer.

Backfills the table model with historical records on first open and monitors the file (plus its parent directory) so subsequent appends and
log rotations propagate into the live view.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, cast, override

from PyQt6.QtCore import QFileSystemWatcher, QObject, QThread, QTimer, pyqtSignal

from intellicrack.core.logging import get_logger
from intellicrack.ui.log_viewer._record import LogRecordDict, parse_json_line


if TYPE_CHECKING:
    from pathlib import Path


_logger = get_logger(__name__)


_INITIAL_LOAD_DEFAULT_BYTES: Final[int] = 5 * 1024 * 1024
_MAX_INCREMENTAL_BYTES: Final[int] = 1 * 1024 * 1024
_READ_RESCHEDULE_MS: Final[int] = 0


def _read_tail_bytes(path: Path, max_bytes: int) -> tuple[bytes, int]:
    """Return the trailing bytes of a file and the file's total size.

    Args:
        path: File to read.
        max_bytes: Maximum trailing bytes to read.

    Returns:
        tuple[bytes, int]: ``(tail_bytes, file_size)``.
    """
    with path.open("rb") as handle:
        handle.seek(0, 2)
        file_size = handle.tell()
        start = max(0, file_size - max_bytes)
        handle.seek(start)
        return handle.read(), file_size


def _parse_tail_lines(raw: bytes, *, skip_first_line: bool) -> list[LogRecordDict]:
    """Decode and parse JSON-Lines bytes into log records.

    Args:
        raw: Raw bytes from the tail of the log file.
        skip_first_line: When ``True``, drop the first line because the
            caller's read started mid-record.

    Returns:
        list[LogRecordDict]: Parsed records (invalid lines skipped).
    """
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if skip_first_line and lines:
        lines = lines[1:]
    records: list[LogRecordDict] = []
    for line in lines:
        parsed = parse_json_line(line)
        if parsed is not None:
            records.append(parsed)
    return records


class InitialLoadWorker(QThread):
    """Background worker that performs the historical tail read.

    Reads up to ``max_bytes`` from the end of the log file, drops the
    (likely partial) first line, parses each remaining line as JSON, and
    emits ``records_ready`` with the resulting list. ``offset_ready``
    reports the byte offset where live tailing should resume.

    Attributes:
        records_ready: Emitted with the parsed historical records.
        offset_ready: Emitted with the next-read byte offset.
    """

    records_ready = pyqtSignal(list)
    offset_ready = pyqtSignal(int)

    def __init__(self, log_path: Path, max_bytes: int, parent: QObject | None = None) -> None:
        """Initialize the worker with the file to read and max-bytes cap.

        Args:
            log_path: Absolute path to the JSON-Lines log file.
            max_bytes: Maximum number of trailing bytes to read.
            parent: Parent :class:`QObject`.
        """
        super().__init__(parent)
        self._log_path = log_path
        self._max_bytes = max_bytes

    @override
    def run(self) -> None:
        """Perform the historical read in a worker thread."""
        records, final_offset = self._safe_load()
        self.records_ready.emit(records)
        self.offset_ready.emit(final_offset)

    def _safe_load(self) -> tuple[list[LogRecordDict], int]:
        """Read and parse the tail, returning empty results on OS errors.

        Returns:
            tuple[list[LogRecordDict], int]: Parsed records and the
                byte offset where live tailing should resume.
        """
        if not self._log_path.exists():
            return [], 0
        try:
            raw, file_size = _read_tail_bytes(self._log_path, self._max_bytes)
        except OSError as exc:
            _logger.warning("log_viewer_initial_load_failed", path=str(self._log_path), error=str(exc))
            return [], 0
        skip_first = file_size > self._max_bytes
        records = _parse_tail_lines(raw, skip_first_line=skip_first)
        return records, file_size


def _make_rotation_notice(path: Path) -> LogRecordDict:
    """Build a synthetic record describing a detected log rotation.

    Args:
        path: Path of the rotated log file.

    Returns:
        LogRecordDict: Synthetic notice inserted into the model.
    """
    return LogRecordDict(
        timestamp=datetime.now(tz=UTC).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
        level="WARNING",
        logger="intellicrack.ui.log_viewer",
        module="_tail_reader",
        function="_detect_rotation",
        line_number=0,
        event="log_file_rotated",
        extras={"path": str(path)},
    )


class LogFileTailReader(QObject):
    """Watches a JSON-Lines log file and emits new records as they appear.

    The reader does an initial backfill on a worker thread, then uses a
    :class:`QFileSystemWatcher` on both the file and its parent directory
    so log rotation (truncate-or-rename) and slow first-write scenarios
    are handled. Each diff read is capped at ``_MAX_INCREMENTAL_BYTES``
    bytes; if more data is available it re-schedules itself via
    :func:`QTimer.singleShot` to keep the GUI responsive.

    Attributes:
        record_emitted: Emitted with a :class:`LogRecordDict` for each
            parsed line, including synthetic rotation notices.
        initial_load_complete: Emitted (with the offset where live
            tailing resumes) once the historical load finishes.
    """

    record_emitted = pyqtSignal(dict)
    initial_load_complete = pyqtSignal(int)

    def __init__(
        self,
        log_path: Path,
        max_initial_bytes: int = _INITIAL_LOAD_DEFAULT_BYTES,
        parent: QObject | None = None,
    ) -> None:
        """Initialize the reader for the given log file.

        Args:
            log_path: Path to the JSON-Lines log file (need not exist
                yet; the directory watcher will pick it up on creation).
            max_initial_bytes: Maximum number of trailing bytes read on
                first load.
            parent: Parent :class:`QObject` for ownership.
        """
        super().__init__(parent)
        self._log_path = log_path
        self._max_initial_bytes = max_initial_bytes
        self._last_offset: int = 0
        self._read_in_progress: bool = False
        self._stopped: bool = False
        self._initial_worker: InitialLoadWorker | None = None
        self._watcher: QFileSystemWatcher | None = None

    def start(self) -> None:
        """Begin the initial historical load and set up file watching.

        Repeated calls are no-ops once a load is in progress. Tests can call :meth:`force_poll` after :meth:`start` if needed.
        """
        if self._stopped or self._initial_worker is not None:
            return
        worker = InitialLoadWorker(self._log_path, self._max_initial_bytes, parent=self)
        worker.records_ready.connect(self._on_initial_records)
        worker.offset_ready.connect(self._on_initial_offset)
        worker.finished.connect(self._on_initial_finished)
        self._initial_worker = worker
        worker.start()

    def stop(self) -> None:
        """Stop watching and tear down internal resources."""
        self._stopped = True
        if self._watcher is not None:
            with contextlib.suppress(TypeError):
                self._watcher.fileChanged.disconnect(self._on_file_changed)
            with contextlib.suppress(TypeError):
                self._watcher.directoryChanged.disconnect(self._on_directory_changed)
            self._watcher.deleteLater()
            self._watcher = None
        if self._initial_worker is not None and self._initial_worker.isRunning():
            self._initial_worker.wait(2000)

    def force_poll(self) -> None:
        """Trigger an immediate incremental read.

        Useful for tests where signals from :class:`QFileSystemWatcher` may be delivered asynchronously.
        """
        self._read_incremental()

    def _on_initial_records(self, records: list[LogRecordDict]) -> None:
        """Push historical records into the model.

        Args:
            records: Parsed historical records.
        """
        for record in records:
            self.record_emitted.emit(cast("dict[str, object]", record))

    def _on_initial_offset(self, offset: int) -> None:
        """Record the offset reached during the historical load.

        Args:
            offset: Byte offset where live tailing should resume.
        """
        self._last_offset = offset
        self.initial_load_complete.emit(offset)

    def _on_initial_finished(self) -> None:
        """Set up file/directory watchers once the historical load finishes."""
        if self._stopped:
            return
        self._install_watcher()
        self._read_incremental()

    def _install_watcher(self) -> None:
        """Install the :class:`QFileSystemWatcher` on file + parent dir."""
        if self._watcher is not None:
            return
        watcher = QFileSystemWatcher(self)
        if self._log_path.exists():
            watcher.addPath(str(self._log_path))
        parent = self._log_path.parent
        if parent.exists():
            watcher.addPath(str(parent))
        watcher.fileChanged.connect(self._on_file_changed)
        watcher.directoryChanged.connect(self._on_directory_changed)
        self._watcher = watcher

    def _on_file_changed(self, _path: str) -> None:
        """Handle a file-changed notification.

        Args:
            _path: Path string from the watcher (unused).
        """
        if self._stopped:
            return
        self._read_incremental()

    def _on_directory_changed(self, _path: str) -> None:
        """Handle a directory-changed notification (catches rotation/recreate).

        Args:
            _path: Path string from the watcher (unused).
        """
        if self._stopped:
            return
        if self._watcher is not None and self._log_path.exists():
            watched = self._watcher.files()
            if str(self._log_path) not in watched:
                self._watcher.addPath(str(self._log_path))
        self._read_incremental()

    def _read_chunk(self) -> tuple[bytes, int, bool]:
        """Read a single chunk of newly appended bytes.

        Detects rotation/truncation by comparing the current file size
        against ``_last_offset``. When rotation is detected, emits the
        synthetic notice and resets the offset before reading.

        Returns:
            tuple[bytes, int, bool]: ``(raw_bytes, new_offset,
                more_pending)``. ``raw_bytes`` is empty when nothing
                new is available.
        """
        with self._log_path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            if size < self._last_offset:
                self.record_emitted.emit(cast("dict[str, object]", _make_rotation_notice(self._log_path)))
                self._last_offset = 0
            if size == self._last_offset:
                return b"", self._last_offset, False
            handle.seek(self._last_offset)
            bytes_to_read = min(size - self._last_offset, _MAX_INCREMENTAL_BYTES)
            raw = handle.read(bytes_to_read)
        new_offset = self._last_offset + len(raw)
        return raw, new_offset, new_offset < size

    def _read_incremental(self) -> None:
        """Read newly appended bytes and emit parsed records."""
        if self._stopped or self._read_in_progress or not self._log_path.exists():
            return

        self._read_in_progress = True
        try:
            raw, new_offset, more_pending = self._read_chunk()
        except OSError as exc:
            _logger.warning("log_viewer_incremental_read_failed", path=str(self._log_path), error=str(exc))
            self._read_in_progress = False
            return

        self._last_offset = new_offset

        if raw:
            text = raw.decode("utf-8", errors="replace")
            for line in text.splitlines():
                parsed = parse_json_line(line)
                if parsed is not None:
                    self.record_emitted.emit(cast("dict[str, object]", parsed))

        self._read_in_progress = False

        if more_pending:
            QTimer.singleShot(_READ_RESCHEDULE_MS, self._read_incremental)
