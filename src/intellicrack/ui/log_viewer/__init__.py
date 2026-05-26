# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Live log viewer package.

Provides a standalone :class:`QMainWindow` (``LogViewerWindow``) that
subscribes to the structlog stream via :class:`QtSignalingHandler` and
backfills history from the on-disk JSON-Lines log file.
"""

from __future__ import annotations

from intellicrack.ui.log_viewer._handler import (
    QtSignalingHandler,
    get_qt_log_handler,
    install_qt_log_handler,
    uninstall_qt_log_handler,
)
from intellicrack.ui.log_viewer._model import LogRecordTableModel
from intellicrack.ui.log_viewer._proxy import LogFilterProxyModel, level_name_to_int
from intellicrack.ui.log_viewer._record import LogRecordDict, parse_json_line, record_to_json_text
from intellicrack.ui.log_viewer._tail_reader import LogFileTailReader
from intellicrack.ui.log_viewer.window import LogRecordDetailsDialog, LogViewerWindow


__all__ = [
    "LogFileTailReader",
    "LogFilterProxyModel",
    "LogRecordDetailsDialog",
    "LogRecordDict",
    "LogRecordTableModel",
    "LogViewerWindow",
    "QtSignalingHandler",
    "get_qt_log_handler",
    "install_qt_log_handler",
    "level_name_to_int",
    "parse_json_line",
    "record_to_json_text",
    "uninstall_qt_log_handler",
]
