# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Background workers for the process panel.

Provides QThread-based workers for querying ProcessManager tracked processes without blocking the UI thread.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QThread, pyqtSignal

from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager, TrackedProcess


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget


_logger = get_logger("ui.panels.process.workers")


class TrackedRefreshWorker(QThread):
    """Background worker for fetching tracked process data without blocking the UI.

    Queries ProcessManager for all tracked processes and their running state
    in a separate thread, then emits the serialized results back to the main thread.

    Attributes:
        refresh_finished: Signal emitted with tracked process data when collection completes.
    """

    refresh_finished: pyqtSignal = pyqtSignal(list)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the TrackedRefreshWorker.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)

    def run(self) -> None:
        """Execute tracked process data collection in the background thread."""
        result: list[dict[str, str | int | None]] = []
        try:
            manager = ProcessManager.get_instance()
            all_tracked: list[TrackedProcess] = manager.get_all_tracked()
            running_pids: set[int | None] = {p.pid for p in manager.get_running_processes()}

            for tracked in all_tracked:
                pid = tracked.pid
                status = "Running" if pid in running_pids else "Stopped"
                registered_str = tracked.registered_at.strftime("%Y-%m-%d %H:%M:%S")
                result.append({
                    "pid": pid,
                    "name": tracked.name,
                    "process_type": tracked.process_type.value,
                    "status": status,
                    "registered_at": registered_str,
                })
        except (RuntimeError, ValueError, KeyError) as e:
            _logger.warning("tracked_refresh_failed", error=str(e))

        self.refresh_finished.emit(result)
