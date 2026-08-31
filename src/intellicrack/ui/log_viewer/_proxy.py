# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Filter proxy for the Log Viewer table.

Combines a minimum log-level filter, a compiled logger-name regex, and a free-text search across the event identifier and the JSON-rendered
extras. Invalid regular expressions silently disable the logger filter.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Final, cast, override

from PyQt6.QtCore import QSortFilterProxyModel, Qt

from intellicrack.core.logging import get_logger
from intellicrack.ui.log_viewer._record import LogRecordDict, extras_to_compact_json


if TYPE_CHECKING:
    from PyQt6.QtCore import QModelIndex, QObject


_logger = get_logger(__name__)

_LEVEL_NAME_TO_INT: Final[dict[str, int]] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def level_name_to_int(name: str) -> int:
    """Return the numeric ``logging`` level for a name, defaulting to ``INFO``.

    Args:
        name: Upper- or lower-case level name (e.g. ``"WARNING"``).

    Returns:
        int: Numeric level, or :data:`logging.INFO` when unknown.
    """
    return _LEVEL_NAME_TO_INT.get(name.upper(), logging.INFO)


class LogFilterProxyModel(QSortFilterProxyModel):
    """Sort/filter proxy applying the viewer's filter state to a model.

    Attributes:
        min_level: Records with a numeric level below this value are
            hidden.
    """

    min_level: int

    def __init__(self, parent: QObject | None = None) -> None:
        """Initialize the proxy with permissive defaults.

        Args:
            parent: Parent :class:`QObject`.
        """
        super().__init__(parent)
        self.min_level = logging.DEBUG
        self._logger_pattern: re.Pattern[str] | None = None
        self._text_query: str = ""
        self._case_sensitive: bool = False
        self.setDynamicSortFilter(True)
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def set_min_level(self, level: int) -> None:
        """Set the minimum numeric level shown.

        Args:
            level: Numeric ``logging`` level (e.g. :data:`logging.WARNING`).
        """
        if self.min_level == level:
            return
        self.min_level = level
        self.invalidateFilter()

    def set_logger_pattern(self, pattern: str) -> None:
        """Set the logger-name regex filter.

        Invalid regular expressions silently clear the filter so the
        viewer remains usable while the user is mid-typing.

        Args:
            pattern: Regular-expression source string. Empty disables
                the filter.
        """
        if not pattern:
            new_pattern: re.Pattern[str] | None = None
        else:
            try:
                new_pattern = re.compile(pattern)
            except re.error:
                _logger.warning("log_viewer_logger_filter_regex_invalid", pattern=pattern, exc_info=True)
                new_pattern = None
        if new_pattern == self._logger_pattern:
            return
        self._logger_pattern = new_pattern
        self.invalidateFilter()

    def logger_pattern_source(self) -> str:
        """Return the source string of the currently compiled logger pattern.

        Returns:
            str: The pattern's source, or empty string when no pattern.
        """
        return "" if self._logger_pattern is None else self._logger_pattern.pattern

    def set_text_query(self, query: str) -> None:
        """Set the free-text search query.

        Args:
            query: Substring to look for in the event identifier or
                the JSON form of the extras.
        """
        if self._text_query == query:
            return
        self._text_query = query
        self.invalidateFilter()

    def set_case_sensitive(self, *, case_sensitive: bool) -> None:
        """Toggle whether the free-text search is case sensitive.

        Args:
            case_sensitive: ``True`` to match exactly as typed.
        """
        if self._case_sensitive == case_sensitive:
            return
        self._case_sensitive = case_sensitive
        self.invalidateFilter()

    @override
    def filterAcceptsRow(
        self,
        source_row: int,
        source_parent: QModelIndex,
    ) -> bool:
        """Return whether the given source row passes all active filters.

        Args:
            source_row: Row index in the source model.
            source_parent: Parent index for hierarchical models (unused
                for the flat log table).

        Returns:
            bool: ``True`` when the row should be visible.
        """
        model = self.sourceModel()
        if model is None:
            return False

        index = model.index(source_row, 0, source_parent)
        if not index.isValid():
            return False
        raw = model.data(index, Qt.ItemDataRole.UserRole)
        if not isinstance(raw, dict):
            return False
        record = cast("LogRecordDict", raw)

        record_level_int = level_name_to_int(record.get("level", "INFO"))
        if record_level_int < self.min_level:
            return False

        if self._logger_pattern is not None and not self._logger_pattern.search(record.get("logger", "")):
            return False

        if self._text_query:
            query = self._text_query if self._case_sensitive else self._text_query.casefold()
            event_text = record.get("event", "")
            extras_text = extras_to_compact_json(record.get("extras", {}))
            haystack = f"{event_text}\n{extras_text}"
            if not self._case_sensitive:
                haystack = haystack.casefold()
            if query not in haystack:
                return False

        return True
