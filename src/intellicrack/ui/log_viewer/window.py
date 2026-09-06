# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Modeless :class:`QMainWindow` exposing the live log stream.

Provides filter controls (min level, logger regex, free-text), pause / resume, auto-scroll, save-as, and per-row details viewing. The window
subscribes to a :class:`QtSignalingHandler` for live records and uses a :class:`LogFileTailReader` to backfill history from the on-disk
file.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Final, override

from PyQt6.QtCore import QByteArray, QModelIndex, QSettings, Qt, QTimer, QUrl
from PyQt6.QtGui import QAction, QDesktopServices, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTableView,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.log_viewer._handler import get_qt_log_handler, install_qt_log_handler
from intellicrack.ui.log_viewer._model import LogRecordTableModel
from intellicrack.ui.log_viewer._proxy import LogFilterProxyModel, level_name_to_int
from intellicrack.ui.log_viewer._record import LogRecordDict, record_to_json_text
from intellicrack.ui.log_viewer._tail_reader import LogFileTailReader
from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from PyQt6.QtGui import QCloseEvent

    from intellicrack.core.config import Config


_logger = get_logger(__name__)


_DEFAULT_LOG_FILENAME: Final[str] = "intellicrack.log"
_LEVELS: Final[tuple[str, ...]] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
_DEFAULT_LEVEL: Final[str] = "INFO"
_SETTINGS_ORG: Final[str] = "Intellicrack"
_SETTINGS_APP: Final[str] = "LogViewer"

_DEFAULT_WIDTH: Final[int] = 1100
_DEFAULT_HEIGHT: Final[int] = 600
_DEFAULT_FILTER_PANEL_WIDTH: Final[int] = 260
_FILTER_PANEL_MIN_WIDTH: Final[int] = 200
_DETAILS_DIALOG_WIDTH: Final[int] = 720
_DETAILS_DIALOG_HEIGHT: Final[int] = 480

_MIN_ROWS: Final[int] = 1_000
_MAX_ROWS: Final[int] = 500_000

_TIME_COLUMN: Final[int] = 0
_LEVEL_COLUMN: Final[int] = 1
_LOGGER_COLUMN: Final[int] = 2
_LOCATION_COLUMN: Final[int] = 3
_EVENT_COLUMN: Final[int] = 4


def _resolve_log_path(config: Config) -> Path:
    """Resolve the active log file path from configuration.

    Args:
        config: Application configuration carrying ``logs_directory``.

    Returns:
        Path: Absolute path to the JSON-Lines log file.
    """
    return Path(config.logs_directory) / _DEFAULT_LOG_FILENAME


def _coerce_int(value: object) -> int | None:
    """Convert a QSettings value into an int when possible.

    Args:
        value: Value retrieved from :class:`QSettings`.

    Returns:
        int | None: Parsed integer, or ``None`` when conversion failed.
    """
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            _logger.warning("log_viewer_settings_int_coerce_failed", raw_value=value, exc_info=True)
            return None
    return None


_TRUTHY_STRINGS: Final[frozenset[str]] = frozenset({"true", "1", "yes", "on"})
_FALSY_STRINGS: Final[frozenset[str]] = frozenset({"false", "0", "no", "off"})


def _coerce_bool(value: object) -> bool | None:
    """Convert a QSettings value into a bool when possible.

    Args:
        value: Value retrieved from :class:`QSettings`.

    Returns:
        bool | None: Parsed boolean, or ``None`` when conversion failed.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUTHY_STRINGS:
            return True
        return False if lowered in _FALSY_STRINGS else None
    return None


def _write_records_jsonl(target: str, records: list[LogRecordDict]) -> int:
    """Serialize log records to a JSON-Lines file.

    Runs on a background worker thread so that saving a large capture
    (up to :data:`_MAX_ROWS` rows) does not block the Qt GUI thread.

    Args:
        target: Destination file path selected by the user.
        records: Records to serialize, one JSON object per line.

    Returns:
        int: Number of records written.
    """
    with Path(target).open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(dict(record), ensure_ascii=False, default=repr))
            handle.write("\n")
    return len(records)


def _open_in_file_browser(folder: Path) -> None:
    """Reveal a directory in the platform's native file browser.

    Delegates to :class:`QDesktopServices`, which on each platform
    invokes the system's URL handler (``ShellExecute`` on Windows,
    ``open`` on macOS, ``xdg-open`` on Linux/BSD).

    Args:
        folder: Directory to open.

    Raises:
        OSError: When :class:`QDesktopServices` refuses the open
            request.
    """
    url = QUrl.fromLocalFile(str(folder))
    if not QDesktopServices.openUrl(url):
        msg = f"QDesktopServices failed to open {folder}"
        raise OSError(msg)


class LogRecordDetailsDialog(QDialog):
    """Modal dialog showing the full JSON of a single log record.

    Attributes:
        record: The record being displayed.
    """

    record: LogRecordDict

    def __init__(self, record: LogRecordDict, parent: QWidget | None = None) -> None:
        """Initialize the dialog with the given record.

        Args:
            record: Normalized log record to display.
            parent: Parent widget.
        """
        super().__init__(parent)
        self.record = record
        self.setWindowTitle("Log Record Details")
        self.resize(_DETAILS_DIALOG_WIDTH, _DETAILS_DIALOG_HEIGHT)
        self._text = QPlainTextEdit(self)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build the dialog's widgets."""
        layout = QVBoxLayout(self)

        self._text.setReadOnly(True)
        self._text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        mono = QFont(FontManager.get_instance().code_font_family)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self._text.setFont(mono)
        self._text.setPlainText(record_to_json_text(self.record))
        layout.addWidget(self._text)

        button_row = QHBoxLayout()
        copy_btn = QPushButton("Copy", self)
        copy_btn.clicked.connect(self._on_copy)
        close_btn = QPushButton("Close", self)
        close_btn.clicked.connect(self.accept)
        button_row.addStretch(1)
        button_row.addWidget(copy_btn)
        button_row.addWidget(close_btn)
        layout.addLayout(button_row)

    @property
    def text(self) -> str:
        """The JSON text currently displayed in the dialog.

        Returns:
            str: Pretty-printed JSON for the record.
        """
        return self._text.toPlainText()

    def _on_copy(self) -> None:
        """Copy the rendered JSON to the system clipboard."""
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(self._text.toPlainText())


class _LogTableView(QTableView):
    """Specialized table view that opens the details dialog on double-click.

    The view is configured for read-only, full-row selection and shows no vertical row headers, matching typical log-viewer UX.
    """

    def __init__(self, proxy: LogFilterProxyModel, parent: QWidget) -> None:
        """Configure the view against the proxy model.

        Args:
            proxy: Filter proxy supplying rows.
            parent: Owning widget.
        """
        super().__init__(parent)
        self.setModel(proxy)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(False)
        self.setShowGrid(False)
        vertical_header = self.verticalHeader()
        if vertical_header is not None:
            vertical_header.hide()
            vertical_header.setDefaultSectionSize(18)
        horizontal_header = self.horizontalHeader()
        if horizontal_header is not None:
            horizontal_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            horizontal_header.setStretchLastSection(True)
            horizontal_header.setSectionResizeMode(_TIME_COLUMN, QHeaderView.ResizeMode.ResizeToContents)
            horizontal_header.setSectionResizeMode(_LEVEL_COLUMN, QHeaderView.ResizeMode.ResizeToContents)
            horizontal_header.setSectionResizeMode(_LOGGER_COLUMN, QHeaderView.ResizeMode.ResizeToContents)
            horizontal_header.setSectionResizeMode(_LOCATION_COLUMN, QHeaderView.ResizeMode.ResizeToContents)
            horizontal_header.setSectionResizeMode(_EVENT_COLUMN, QHeaderView.ResizeMode.Stretch)
        self.doubleClicked.connect(self._on_double_clicked)
        _logger.debug("log_viewer_table_view_initialized")

    def _on_double_clicked(self, index: QModelIndex) -> None:
        """Open the :class:`LogRecordDetailsDialog` for the clicked row.

        Args:
            index: Proxy index of the clicked cell.
        """
        if not index.isValid():
            return
        proxy = self.model()
        if not isinstance(proxy, LogFilterProxyModel):
            return
        source_index = proxy.mapToSource(index)
        source_model = proxy.sourceModel()
        if not isinstance(source_model, LogRecordTableModel):
            return
        record = source_model.record_at(source_index.row())
        if record is None:
            return
        dialog = LogRecordDetailsDialog(record, parent=self)
        dialog.exec()


class LogViewerWindow(QMainWindow):
    """Modeless log viewer window.

    Subscribes to the global :class:`QtSignalingHandler` and tails the
    on-disk JSON-Lines log to backfill history. Owned by the main
    window; geometry and filter state persist via :class:`QSettings`.

    Attributes:
        log_path: Path to the JSON-Lines log file currently displayed.
    """

    log_path: Path

    def __init__(self, config: Config, parent: QWidget | None = None) -> None:
        """Initialize the viewer for the given application config.

        Args:
            config: Application configuration providing the logs path.
            parent: Optional parent window (typically the
                :class:`MainWindow`).
        """
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, on=False)
        self.setWindowTitle("Intellicrack - Log Viewer")
        self.resize(_DEFAULT_WIDTH, _DEFAULT_HEIGHT)

        self._config = config
        self.log_path = _resolve_log_path(config)

        self._handler = get_qt_log_handler() or install_qt_log_handler()
        self._model = LogRecordTableModel(parent=self)
        self._proxy = LogFilterProxyModel(parent=self)
        self._proxy.setSourceModel(self._model)
        self._proxy.set_min_level(level_name_to_int(_DEFAULT_LEVEL))

        self._tail_reader = LogFileTailReader(self.log_path, parent=self)

        self._auto_scroll: bool = True
        self._pause_action: QAction | None = None
        self._level_combo: QComboBox | None = None
        self._logger_regex_edit: QLineEdit | None = None
        self._text_query_edit: QLineEdit | None = None
        self._case_check: QCheckBox | None = None
        self._max_rows_spin: QSpinBox | None = None
        self._auto_scroll_check: QCheckBox | None = None
        self._table_view: _LogTableView | None = None
        self._status_path_label: QLabel | None = None
        self._status_counts_label: QLabel | None = None

        self._build_ui()
        self._connect_signals()
        self._restore_settings()
        self._tail_reader.start()

    @property
    def model(self) -> LogRecordTableModel:
        """The underlying log-record table model.

        Returns:
            LogRecordTableModel: The source model backing the table.
        """
        return self._model

    @property
    def proxy(self) -> LogFilterProxyModel:
        """The filter proxy connected between model and view.

        Returns:
            LogFilterProxyModel: The active proxy model.
        """
        return self._proxy

    @property
    def pause_action(self) -> QAction | None:
        """The toolbar Pause action, available once the toolbar is built.

        Returns:
            QAction | None: The Pause :class:`QAction`, or ``None`` if
                the UI is not yet constructed.
        """
        return self._pause_action

    def is_paused(self) -> bool:
        """Return whether the live capture is currently paused.

        Returns:
            bool: ``True`` when the handler is suppressing emission.
        """
        return self._handler.paused

    def set_min_level(self, level: int) -> None:
        """Programmatically set the proxy's minimum level filter.

        Args:
            level: Numeric ``logging`` level (e.g. :data:`logging.WARNING`).
        """
        self._proxy.set_min_level(level)

    def clear(self) -> None:
        """Clear all records from the model.

        Public entry point exposed for callers that don't have access to the toolbar's Clear action.
        """
        self._on_clear()

    def _build_ui(self) -> None:
        """Assemble toolbars, filter panel, table, and status bar."""
        central = QWidget(self)
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(4, 4, 4, 4)

        self._build_toolbar()

        splitter = QSplitter(Qt.Orientation.Horizontal, central)
        splitter.setChildrenCollapsible(False)
        layout.addWidget(splitter)

        filter_panel = self._build_filter_panel()
        splitter.addWidget(filter_panel)

        table_view = _LogTableView(self._proxy, splitter)
        self._table_view = table_view
        splitter.addWidget(table_view)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([_DEFAULT_FILTER_PANEL_WIDTH, _DEFAULT_WIDTH - _DEFAULT_FILTER_PANEL_WIDTH])

        self._build_status_bar()

    def _build_toolbar(self) -> None:
        """Construct and attach the main toolbar."""
        toolbar = QToolBar("Log Viewer Toolbar", self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        pause_action = QAction("Pause", self)
        pause_action.setCheckable(True)

        def _pause_slot(state: int) -> None:
            """Pause or resume live log tailing from the toolbar pause action.

            Args:
                state: Qt ``toggled`` payload; nonzero means live tail is paused.
            """
            self._on_pause_toggled(checked=bool(state))

        pause_action.toggled.connect(_pause_slot)
        toolbar.addAction(pause_action)
        self._pause_action = pause_action

        clear_action = QAction("Clear", self)
        clear_action.triggered.connect(self._on_clear)
        toolbar.addAction(clear_action)

        toolbar.addSeparator()

        save_selected_action = QAction("Save Selected As...", self)
        save_selected_action.triggered.connect(self._on_save_selected)
        toolbar.addAction(save_selected_action)

        save_all_action = QAction("Save All As...", self)
        save_all_action.triggered.connect(self._on_save_all)
        toolbar.addAction(save_all_action)

        toolbar.addSeparator()

        open_dir_action = QAction("Open Logs Folder", self)
        open_dir_action.triggered.connect(self._on_open_logs_folder)
        toolbar.addAction(open_dir_action)

        reload_action = QAction("Reload from Disk", self)
        reload_action.triggered.connect(self._on_reload_from_disk)
        toolbar.addAction(reload_action)

    def _build_status_bar(self) -> None:
        """Construct and attach the status bar."""
        status = QStatusBar(self)
        self.setStatusBar(status)
        self._status_counts_label = QLabel("0 / 0", status)
        self._status_path_label = QLabel(str(self.log_path), status)
        self._status_path_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        status.addWidget(self._status_counts_label)
        status.addPermanentWidget(self._status_path_label, 1)

    def _build_filter_panel(self) -> QWidget:
        """Build the left-hand filter controls panel.

        Returns:
            QWidget: The configured panel.
        """
        panel = QWidget(self)
        panel.setMinimumWidth(_FILTER_PANEL_MIN_WIDTH)
        form = QVBoxLayout(panel)
        form.setContentsMargins(8, 8, 8, 8)
        self._add_level_combo(panel, form)
        self._add_logger_regex_edit(panel, form)
        self._add_text_query_edit(panel, form)
        self._add_case_sensitive_check(panel, form)
        form.addSpacing(8)
        self._add_max_rows_spin(panel, form)
        self._add_auto_scroll_check(panel, form)
        form.addStretch(1)
        return panel

    def _add_level_combo(self, panel: QWidget, form: QVBoxLayout) -> None:
        """Add the minimum-level combo to the filter panel.

        Args:
            panel: Parent panel widget.
            form: Layout to append into.
        """
        form.addWidget(QLabel("Minimum Level", panel))
        combo = QComboBox(panel)
        combo.addItems(_LEVELS)
        combo.setCurrentText(_DEFAULT_LEVEL)
        combo.currentTextChanged.connect(self._on_level_changed)
        self._level_combo = combo
        form.addWidget(combo)

    def _add_logger_regex_edit(self, panel: QWidget, form: QVBoxLayout) -> None:
        """Add the logger-regex line edit to the filter panel.

        Args:
            panel: Parent panel widget.
            form: Layout to append into.
        """
        form.addWidget(QLabel("Logger Name (regex)", panel))
        edit = QLineEdit(panel)
        edit.setPlaceholderText("e.g. ^intellicrack\\.core")
        edit.textChanged.connect(self._on_logger_pattern_changed)
        self._logger_regex_edit = edit
        form.addWidget(edit)

    def _add_text_query_edit(self, panel: QWidget, form: QVBoxLayout) -> None:
        """Add the free-text search edit to the filter panel.

        Args:
            panel: Parent panel widget.
            form: Layout to append into.
        """
        form.addWidget(QLabel("Search Text", panel))
        edit = QLineEdit(panel)
        edit.setPlaceholderText("substring of event or extras")
        edit.textChanged.connect(self._on_text_query_changed)
        self._text_query_edit = edit
        form.addWidget(edit)

    def _add_case_sensitive_check(self, panel: QWidget, form: QVBoxLayout) -> None:
        """Add the case-sensitive checkbox to the filter panel.

        Args:
            panel: Parent panel widget.
            form: Layout to append into.
        """
        check = QCheckBox("Case sensitive", panel)

        def _case_sensitive_slot(state: int) -> None:
            """Rebuild the log filter when the Case sensitive checkbox changes.

            Args:
                state: Qt ``toggled`` payload; nonzero enables case-sensitive match.
            """
            self._on_case_sensitive_changed(checked=bool(state))

        check.toggled.connect(_case_sensitive_slot)
        self._case_check = check
        form.addWidget(check)

    def _add_max_rows_spin(self, panel: QWidget, form: QVBoxLayout) -> None:
        """Add the max-rows spin box to the filter panel.

        Args:
            panel: Parent panel widget.
            form: Layout to append into.
        """
        form.addWidget(QLabel("Max Rows", panel))
        spin = QSpinBox(panel)
        spin.setRange(_MIN_ROWS, _MAX_ROWS)
        spin.setSingleStep(1_000)
        spin.setValue(self._model.max_rows)
        spin.valueChanged.connect(self._on_max_rows_changed)
        self._max_rows_spin = spin
        form.addWidget(spin)

    def _add_auto_scroll_check(self, panel: QWidget, form: QVBoxLayout) -> None:
        """Add the auto-scroll checkbox to the filter panel.

        Args:
            panel: Parent panel widget.
            form: Layout to append into.
        """
        check = QCheckBox("Auto-scroll to newest", panel)
        check.setChecked(True)

        def _auto_scroll_slot(state: int) -> None:
            """Enable or disable follow-tail scrolling from the Auto-scroll checkbox.

            Args:
                state: Qt ``toggled`` payload; nonzero keeps the view on the newest row.
            """
            self._on_auto_scroll_toggled(checked=bool(state))

        check.toggled.connect(_auto_scroll_slot)
        self._auto_scroll_check = check
        form.addWidget(check)

    def _connect_signals(self) -> None:
        """Wire the handler, tail reader, and model into the UI."""
        self._handler.record_received.connect(self._model.append_record)
        self._tail_reader.record_emitted.connect(self._model.append_record)
        self._tail_reader.initial_load_complete.connect(self._on_initial_load_complete)
        self._model.rowsInserted.connect(self._on_rows_inserted)
        self._model.modelReset.connect(self._refresh_status)
        self._proxy.rowsInserted.connect(self._refresh_status_no_args)
        self._proxy.rowsRemoved.connect(self._refresh_status_no_args)
        self._proxy.layoutChanged.connect(self._refresh_status)

    def _on_pause_toggled(self, *, checked: bool) -> None:
        """Toggle the handler's paused flag.

        Args:
            checked: Toggle state of the Pause action.
        """
        self._handler.set_paused(paused=checked)
        if self._pause_action is not None:
            self._pause_action.setText("Resume" if checked else "Pause")

    def _on_clear(self) -> None:
        """Clear the model in response to the Clear action."""
        self._model.clear()
        self._refresh_status()

    def _on_save_selected(self) -> None:
        """Save the currently selected rows as JSON Lines."""
        if self._table_view is None:
            return
        selection_model = self._table_view.selectionModel()
        if selection_model is None:
            return
        records: list[LogRecordDict] = []
        for proxy_index in selection_model.selectedRows():
            source_index = self._proxy.mapToSource(proxy_index)
            record = self._model.record_at(source_index.row())
            if record is not None:
                records.append(record)
        if not records:
            QMessageBox.information(self, "Save Selected", "No rows selected.")
            return
        self._save_records(records, default_name="log_selected.jsonl")

    def _on_save_all(self) -> None:
        """Save every visible row (post-filter) as JSON Lines."""
        records: list[LogRecordDict] = []
        for proxy_row in range(self._proxy.rowCount()):
            source_index = self._proxy.mapToSource(self._proxy.index(proxy_row, 0))
            record = self._model.record_at(source_index.row())
            if record is not None:
                records.append(record)
        self._save_records(records, default_name="log_visible.jsonl")

    def _save_records(self, records: list[LogRecordDict], default_name: str) -> None:
        """Serialize records to a user-selected JSON-Lines file.

        The actual serialize-and-write work runs on a background
        :class:`GenericCallableWorker` thread so that saving a large
        capture (up to :data:`_MAX_ROWS` rows) never blocks the Qt GUI
        thread.

        Args:
            records: Records to save.
            default_name: Suggested filename.
        """
        if not records:
            QMessageBox.information(self, "Save Logs", "No records to save.")
            return
        target, _ = QFileDialog.getSaveFileName(
            self,
            "Save Log Records",
            default_name,
            "JSON Lines (*.jsonl);;All Files (*)",
        )
        if not target:
            return

        def _on_finished(result: object) -> None:
            """Log successful completion of the background save worker.

            Args:
                result: Record count returned by the JSONL write helper.
            """
            _logger.debug("log_viewer_save_records_succeeded", target=target, record_count=result)

        def _on_error(exc: object) -> None:
            """Warn the user when the background save worker fails.

            Args:
                exc: Exception or error payload from the worker.
            """
            error_obj = exc if isinstance(exc, BaseException) else RuntimeError(repr(exc))
            QMessageBox.warning(self, "Save Logs", f"Failed to save log records: {error_obj}")

        worker = GenericCallableWorker(_write_records_jsonl, target, records, parent=self)
        worker.call_finished.connect(_on_finished)
        worker.call_error.connect(_on_error)
        worker.start()

    def _on_open_logs_folder(self) -> None:
        """Open the logs directory in the operating system file browser."""
        folder = self.log_path.parent
        if not folder.exists():
            QMessageBox.warning(self, "Open Logs Folder", f"Logs directory does not exist: {folder}")
            return
        try:
            _open_in_file_browser(folder)
        except OSError as exc:
            QMessageBox.warning(self, "Open Logs Folder", f"Failed to open {folder}: {exc}")

    def _on_reload_from_disk(self) -> None:
        """Replace the model contents with a fresh tail of the log file."""
        self._tail_reader.stop()
        self._tail_reader.deleteLater()
        self._model.clear()
        new_reader = LogFileTailReader(self.log_path, parent=self)
        new_reader.record_emitted.connect(self._model.append_record)
        new_reader.initial_load_complete.connect(self._on_initial_load_complete)
        self._tail_reader = new_reader
        self._tail_reader.start()

    def _on_level_changed(self, text: str) -> None:
        """Update the proxy's minimum-level filter.

        Args:
            text: Level name selected in the combo box.
        """
        self._proxy.set_min_level(level_name_to_int(text))

    def _on_logger_pattern_changed(self, pattern: str) -> None:
        """Update the proxy's logger-name regex filter.

        Args:
            pattern: Regular-expression source.
        """
        self._proxy.set_logger_pattern(pattern)

    def _on_text_query_changed(self, query: str) -> None:
        """Update the proxy's free-text filter.

        Args:
            query: Substring to filter by.
        """
        self._proxy.set_text_query(query)

    def _on_case_sensitive_changed(self, *, checked: bool) -> None:
        """Toggle case sensitivity on the free-text filter.

        Args:
            checked: ``True`` to enable case sensitivity.
        """
        self._proxy.set_case_sensitive(case_sensitive=checked)

    def _on_max_rows_changed(self, value: int) -> None:
        """Update the model's row cap.

        Args:
            value: New row cap from the spin box.
        """
        self._model.set_max_rows(value)

    def _on_auto_scroll_toggled(self, *, checked: bool) -> None:
        """Update the auto-scroll flag.

        Args:
            checked: ``True`` to keep the view scrolled to the newest
                row on insert.
        """
        self._auto_scroll = checked

    def _on_rows_inserted(self, _parent: QModelIndex, _first: int, _last: int) -> None:
        """Scroll the view to the bottom when new rows arrive.

        Args:
            _parent: Parent index (unused).
            _first: First inserted source row (unused).
            _last: Last inserted source row (unused).
        """
        if self._auto_scroll and self._table_view is not None:
            QTimer.singleShot(0, self._table_view.scrollToBottom)
        self._refresh_status()

    def _on_initial_load_complete(self, offset: int) -> None:
        """Log the initial load completion for diagnostics.

        Args:
            offset: Byte offset where live tailing resumes.
        """
        _logger.debug("log_viewer_initial_load_complete", offset=offset, path=str(self.log_path))

    def _refresh_status_no_args(self, *_args: object) -> None:
        """Adapter slot for signals that emit unused index/range arguments.

        Args:
            *_args: Unused signal arguments forwarded by Qt.
        """
        self._refresh_status()

    def _refresh_status(self) -> None:
        """Update the visible/total counter and log-file path in the status bar."""
        if self._status_counts_label is not None:
            visible = self._proxy.rowCount()
            total = self._model.rowCount()
            self._status_counts_label.setText(f"{visible} visible / {total} total")
        if self._status_path_label is not None:
            self._status_path_label.setText(str(self.log_path))

    def _restore_geometry(self, settings: QSettings) -> None:
        """Restore window geometry/state from settings.

        Args:
            settings: QSettings instance to read from.
        """
        geometry_obj = settings.value("geometry")
        if isinstance(geometry_obj, QByteArray):
            self.restoreGeometry(geometry_obj)
        state_obj = settings.value("state")
        if isinstance(state_obj, QByteArray):
            self.restoreState(state_obj)

    def _restore_filters(self, settings: QSettings) -> None:
        """Restore filter widget values and proxy state from settings.

        Args:
            settings: QSettings instance to read from.
        """
        level = settings.value("filter/min_level")
        if isinstance(level, str) and level.upper() in _LEVELS and self._level_combo is not None:
            self._level_combo.setCurrentText(level.upper())
            self._proxy.set_min_level(level_name_to_int(level))

        logger_pattern = settings.value("filter/logger_pattern")
        if isinstance(logger_pattern, str) and self._logger_regex_edit is not None:
            self._logger_regex_edit.setText(logger_pattern)
            self._proxy.set_logger_pattern(logger_pattern)

        text_query = settings.value("filter/text_query")
        if isinstance(text_query, str) and self._text_query_edit is not None:
            self._text_query_edit.setText(text_query)
            self._proxy.set_text_query(text_query)

        case_sensitive_bool = _coerce_bool(settings.value("filter/case_sensitive"))
        if case_sensitive_bool is not None and self._case_check is not None:
            self._case_check.setChecked(case_sensitive_bool)
            self._proxy.set_case_sensitive(case_sensitive=case_sensitive_bool)

        max_rows_val = settings.value("filter/max_rows")
        max_rows = _coerce_int(max_rows_val)
        if max_rows is not None and self._max_rows_spin is not None:
            self._max_rows_spin.setValue(max_rows)
            self._model.set_max_rows(max_rows)

        auto_scroll_bool = _coerce_bool(settings.value("filter/auto_scroll"))
        if auto_scroll_bool is not None and self._auto_scroll_check is not None:
            self._auto_scroll_check.setChecked(auto_scroll_bool)
            self._auto_scroll = auto_scroll_bool

    @staticmethod
    def _build_settings() -> QSettings:
        r"""Construct the viewer's :class:`QSettings` using explicit IniFormat.

        Using :attr:`QSettings.Format.IniFormat` keeps the viewer's
        geometry and filter state in a portable ``.ini`` file under the
        user scope rather than the Windows registry (the default
        ``QSettings(org, app)`` constructor uses ``NativeFormat``,
        i.e. ``HKEY_CURRENT_USER\Software\...`` on Windows). Routing
        through a single helper also lets tests redirect the path via
        :meth:`QSettings.setPath` for ``IniFormat`` and have it actually
        take effect.

        Returns:
            QSettings: User-scope INI-format settings handle for the
                viewer.
        """
        return QSettings(
            QSettings.Format.IniFormat,
            QSettings.Scope.UserScope,
            _SETTINGS_ORG,
            _SETTINGS_APP,
        )

    def _restore_settings(self) -> None:
        """Restore geometry and filter state from :class:`QSettings`."""
        settings = self._build_settings()
        self._restore_geometry(settings)
        self._restore_filters(settings)

    def _save_settings(self) -> None:
        """Persist geometry and filter state to :class:`QSettings`."""
        settings = self._build_settings()
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("state", self.saveState())
        if self._level_combo is not None:
            settings.setValue("filter/min_level", self._level_combo.currentText())
        if self._logger_regex_edit is not None:
            settings.setValue("filter/logger_pattern", self._logger_regex_edit.text())
        if self._text_query_edit is not None:
            settings.setValue("filter/text_query", self._text_query_edit.text())
        if self._case_check is not None:
            settings.setValue("filter/case_sensitive", self._case_check.isChecked())
        if self._max_rows_spin is not None:
            settings.setValue("filter/max_rows", self._max_rows_spin.value())
        if self._auto_scroll_check is not None:
            settings.setValue("filter/auto_scroll", self._auto_scroll_check.isChecked())
        settings.sync()

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """Persist settings and detach the tail reader when the window closes.

        Args:
            a0: Close event from Qt.
        """
        self._save_settings()
        self._tail_reader.stop()
        with contextlib.suppress(TypeError):
            self._handler.record_received.disconnect(self._model.append_record)
        if a0 is not None:
            a0.accept()
        super().closeEvent(a0)
