# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Qt table model backing the Log Viewer.

Holds a bounded ring buffer of :class:`LogRecordDict` rows, batches incoming records through a short coalescing timer for high-volume
streams, and provides level-based foreground and background colors so WARNING / ERROR / CRITICAL records remain scannable.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Final, cast, override

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from PyQt6.QtGui import QColor

from intellicrack.ui.log_viewer._record import LogRecordDict, extras_to_compact_json
from intellicrack.ui.resources.theme_manager import ThemeManager


if TYPE_CHECKING:
    from collections.abc import Iterable

    from PyQt6.QtCore import QObject


_DEFAULT_MAX_ROWS: Final[int] = 50_000
_MIN_MAX_ROWS: Final[int] = 1_000
_MAX_MAX_ROWS: Final[int] = 500_000
_COALESCE_INTERVAL_MS: Final[int] = 50

_COLUMN_TIME: Final[int] = 0
_COLUMN_LEVEL: Final[int] = 1
_COLUMN_LOGGER: Final[int] = 2
_COLUMN_LOCATION: Final[int] = 3
_COLUMN_EVENT: Final[int] = 4
_COLUMN_EXTRAS: Final[int] = 5

_COLUMN_COUNT: Final[int] = 6

_HEADERS: Final[tuple[str, ...]] = ("Time", "Level", "Logger", "Function:Line", "Event", "Extras")

_TINT_ALPHA: Final[int] = 48
_LUMINANCE_MIDPOINT: Final[float] = 0.5
_LUMINANCE_RED_WEIGHT: Final[float] = 0.299
_LUMINANCE_GREEN_WEIGHT: Final[float] = 0.587
_LUMINANCE_BLUE_WEIGHT: Final[float] = 0.114


def _flatten_for_display(text: str) -> str:
    """Collapse newlines and tabs so multi-line text fits a single row.

    Args:
        text: Source text potentially containing newlines.

    Returns:
        str: Display-friendly text with whitespace collapsed.
    """
    if not text:
        return ""
    if "\n" not in text and "\t" not in text:
        return text
    return " ".join(part for part in text.replace("\t", " ").splitlines() if part).strip() or text.strip()


class LogRecordTableModel(QAbstractTableModel):
    """Bounded ring-buffer table model for log records.

    Incoming records are buffered into ``_pending`` and flushed in a
    single ``beginInsertRows`` transaction on a 50 ms timer. The buffer
    is capped at ``max_rows`` and evicts the oldest entries via
    ``beginRemoveRows`` so views stay consistent under load.

    Attributes:
        max_rows: Soft cap on the number of stored rows.
    """

    max_rows: int

    def __init__(
        self,
        max_rows: int = _DEFAULT_MAX_ROWS,
        parent: QObject | None = None,
    ) -> None:
        """Initialize the model with the given soft row cap.

        Args:
            max_rows: Maximum number of rows kept in the ring buffer.
            parent: Parent :class:`QObject` for ownership.
        """
        super().__init__(parent)
        self.max_rows = max(_MIN_MAX_ROWS, min(_MAX_MAX_ROWS, max_rows))
        self._records: deque[LogRecordDict] = deque(maxlen=self.max_rows)
        self._pending: deque[LogRecordDict] = deque()
        self._drain_timer = QTimer(self)
        self._drain_timer.setSingleShot(True)
        self._drain_timer.setInterval(_COALESCE_INTERVAL_MS)
        self._drain_timer.timeout.connect(self._drain_pending)
        self._total_received: int = 0
        self._theme_manager = ThemeManager.get_instance()
        self._level_foregrounds: dict[str, QColor] = {}
        self._level_backgrounds: dict[str, QColor] = {}
        self._resolve_level_colors()
        self._theme_manager.theme_changed.connect(self._on_theme_changed)

    @property
    def total_received(self) -> int:
        """Total number of records ever appended.

        Returns:
            int: Cumulative count, including evicted records.
        """
        return self._total_received

    @staticmethod
    def _contrasting_text_color(background: QColor) -> QColor:
        """Return black or white, whichever contrasts better with a background.

        Args:
            background: Solid background color a badge-style cell paints text over.

        Returns:
            QColor: Black for light backgrounds, white for dark ones, chosen by
                perceived (Rec. 601) relative luminance.
        """
        luminance = (
            _LUMINANCE_RED_WEIGHT * background.red()
            + _LUMINANCE_GREEN_WEIGHT * background.green()
            + _LUMINANCE_BLUE_WEIGHT * background.blue()
        ) / 255.0
        if luminance > _LUMINANCE_MIDPOINT:
            return QColor(0, 0, 0)
        return QColor(255, 255, 255)

    def _resolve_level_colors(self) -> None:
        """Resolve per-level foreground and background colors from the active theme.

        DEBUG and INFO map to the theme's muted and primary foreground so both stay readable against the active background (fixing white-on-
        white INFO text under the light theme). WARNING and ERROR keep their semantic hue with a faint tint, while CRITICAL renders as a
        solid badge with a contrast-picked foreground so the three severities remain distinguishable in both light and dark themes.
        """
        colors = self._theme_manager.get_analysis_colors()
        foreground = colors["foreground"]
        muted = colors["muted"]
        warning = colors["warning"]
        error = colors["error"]

        critical_background = QColor(error)
        self._level_foregrounds = {
            "DEBUG": QColor(muted),
            "INFO": QColor(foreground),
            "WARNING": QColor(warning),
            "ERROR": QColor(error),
            "CRITICAL": self._contrasting_text_color(critical_background),
        }

        warning_background = QColor(warning)
        warning_background.setAlpha(_TINT_ALPHA)
        error_background = QColor(error)
        error_background.setAlpha(_TINT_ALPHA)
        self._level_backgrounds = {
            "WARNING": warning_background,
            "ERROR": error_background,
            "CRITICAL": critical_background,
        }

    def level_foreground(self, level: str) -> QColor | None:
        """Return the resolved foreground color for a log level.

        Args:
            level: Log level name (e.g. ``"INFO"``).

        Returns:
            QColor | None: The theme-resolved foreground color, or ``None`` when
                the level has no dedicated color.
        """
        return self._level_foregrounds.get(level)

    def level_background(self, level: str) -> QColor | None:
        """Return the resolved background color for a log level.

        Args:
            level: Log level name (e.g. ``"CRITICAL"``).

        Returns:
            QColor | None: The theme-resolved background color, or ``None`` when
                the level has no background override.
        """
        return self._level_backgrounds.get(level)

    def _on_theme_changed(self, _theme_name: str) -> None:
        """Re-resolve level colors and repaint existing rows after a theme switch.

        Args:
            _theme_name: Resolved theme name emitted by :class:`ThemeManager`
                (unused; colors are pulled from the manager directly).
        """
        self._resolve_level_colors()
        row_count = len(self._records)
        if row_count == 0:
            return
        top_left = self.index(0, 0)
        bottom_right = self.index(row_count - 1, _COLUMN_COUNT - 1)
        self.dataChanged.emit(
            top_left,
            bottom_right,
            [Qt.ItemDataRole.ForegroundRole, Qt.ItemDataRole.BackgroundRole],
        )

    def append_record(self, record: dict[str, object]) -> None:
        """Queue a record for the next coalesced insert.

        Args:
            record: Normalized log record (treated as
                :class:`LogRecordDict`).
        """
        self._pending.append(cast("LogRecordDict", record))
        if not self._drain_timer.isActive():
            self._drain_timer.start()

    def flush(self) -> None:
        """Force-drain pending records into the model immediately.

        Useful in tests and at shutdown to avoid losing buffered rows.
        """
        if self._drain_timer.isActive():
            self._drain_timer.stop()
        self._drain_pending()

    def _drain_pending(self) -> None:
        """Move all queued records into the ring buffer in one transaction."""
        if not self._pending:
            return

        incoming = list(self._pending)
        self._pending.clear()
        self._total_received += len(incoming)

        existing_count = len(self._records)
        capacity = self.max_rows
        keep_existing_count = max(0, capacity - len(incoming))
        evict_count = existing_count - keep_existing_count

        if evict_count > 0:
            self.beginRemoveRows(QModelIndex(), 0, evict_count - 1)
            for _ in range(evict_count):
                self._records.popleft()
            self.endRemoveRows()

        first_new = len(self._records)
        insert_count = min(len(incoming), capacity)
        records_to_insert = incoming[-insert_count:] if insert_count < len(incoming) else incoming

        if insert_count == 0:
            return

        self.beginInsertRows(QModelIndex(), first_new, first_new + insert_count - 1)
        for record in records_to_insert:
            self._records.append(record)
        self.endInsertRows()

    def clear(self) -> None:
        """Remove all records and pending buffers from the model."""
        self._pending.clear()
        if not self._records:
            return
        self.beginResetModel()
        self._records.clear()
        self.endResetModel()

    def set_max_rows(self, max_rows: int) -> None:
        """Update the row cap, evicting oldest rows if necessary.

        Args:
            max_rows: New row cap; clamped to ``[1_000, 500_000]``.
        """
        clamped = max(_MIN_MAX_ROWS, min(_MAX_MAX_ROWS, max_rows))
        if clamped == self.max_rows:
            return
        self.max_rows = clamped

        evict_count = max(0, len(self._records) - clamped)
        if evict_count > 0:
            self.beginRemoveRows(QModelIndex(), 0, evict_count - 1)
            for _ in range(evict_count):
                self._records.popleft()
            self.endRemoveRows()

        new_buffer: deque[LogRecordDict] = deque(self._records, maxlen=clamped)
        self._records = new_buffer

    def record_at(self, row: int) -> LogRecordDict | None:
        """Return the record at the given row, if any.

        Args:
            row: Row index into the underlying ring buffer.

        Returns:
            LogRecordDict | None: The record, or ``None`` when out of
                range.
        """
        return self._records[row] if 0 <= row < len(self._records) else None

    def all_records(self) -> Iterable[LogRecordDict]:
        """Iterate over all stored records.

        Returns:
            Iterable[LogRecordDict]: Iterator over the ring buffer.
        """
        return tuple(self._records)

    @override
    def rowCount(self, parent: QModelIndex | None = None) -> int:
        """Return the number of rows currently stored.

        Args:
            parent: Parent index; non-default values yield zero per
                table-model conventions.

        Returns:
            int: Row count.
        """
        return 0 if parent is not None and parent.isValid() else len(self._records)

    @override
    def columnCount(self, parent: QModelIndex | None = None) -> int:
        """Return the number of columns exposed by the model.

        Args:
            parent: Parent index; non-default values yield zero per
                table-model conventions.

        Returns:
            int: Fixed column count.
        """
        return 0 if parent is not None and parent.isValid() else _COLUMN_COUNT

    @override
    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        """Return header text for the given section and orientation.

        Args:
            section: Column or row index.
            orientation: ``Horizontal`` for column headers.
            role: Display role; only ``DisplayRole`` returns header text.

        Returns:
            object: Header text for display roles, otherwise ``None``.
        """
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation != Qt.Orientation.Horizontal:
            return None
        return _HEADERS[section] if 0 <= section < _COLUMN_COUNT else None

    @override
    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        """Return cell data for the given index and role.

        Args:
            index: Cell index.
            role: Item data role.

        Returns:
            object: Cell value for display/edit roles, the raw record
                for ``UserRole``, or ``None`` otherwise.
        """
        if not index.isValid():
            return None
        row = index.row()
        if row < 0 or row >= len(self._records):
            return None

        record = self._records[row]
        column = index.column()

        if role == Qt.ItemDataRole.UserRole:
            return record
        if role == Qt.ItemDataRole.ForegroundRole:
            return self._level_foregrounds.get(record["level"])
        if role == Qt.ItemDataRole.BackgroundRole:
            return self._level_backgrounds.get(record["level"])
        if role not in {Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole}:
            return None

        if column == _COLUMN_TIME:
            return record["timestamp"]
        if column == _COLUMN_LEVEL:
            return record["level"]
        if column == _COLUMN_LOGGER:
            return record["logger"]
        if column == _COLUMN_LOCATION:
            func = record["function"]
            line = record["line_number"]
            if func:
                return f"{func}:{line}" if line else func
            if line:
                return str(line)
            return record["module"]
        if column == _COLUMN_EVENT:
            return _flatten_for_display(record["event"])
        if column == _COLUMN_EXTRAS:
            return _flatten_for_display(extras_to_compact_json(record["extras"]))
        return None
