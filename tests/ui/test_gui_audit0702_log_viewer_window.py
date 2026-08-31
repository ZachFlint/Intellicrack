# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for GUI-audit findings M2, M40 and L4 in the Log Viewer window.

M2 -- ``_on_save_all``/``_save_records`` used to build the full record list
and serialize+write it with a plain synchronous ``for`` loop directly inside
the toolbar action's slot, blocking the Qt GUI thread for the duration of the
write. The fix moves the serialize-and-write work into the module-level
``_write_records_jsonl`` helper and dispatches it through a background
:class:`~intellicrack.ui.panels.async_bridge.GenericCallableWorker` ``QThread``,
returning from the slot before the write completes.

M40 -- the table header left the Logger, Function:Line and Event columns at
Qt's default ``Interactive`` resize mode (fixed ~100px), so the two most
information-dense columns in a log viewer started every session visually
clipped. The fix sets ``ResizeToContents`` on Logger/Function:Line and
``Stretch`` on Event.

L4 -- the horizontal ``QSplitter`` housing the filter panel kept Qt's default
``childrenCollapsible=True`` and the filter panel had no minimum width, so a
small drag of the splitter handle toward the left edge snapped the whole
filter panel to 0px with no restore affordance. The fix calls
``splitter.setChildrenCollapsible(False)`` and gives the filter panel
``setMinimumWidth(_FILTER_PANEL_MIN_WIDTH)``.

Each test below drives real Qt objects (:class:`LogViewerWindow`,
``_LogTableView``, ``QSplitter``, and a real background
``GenericCallableWorker`` thread) -- no mocks stand in for the behavior under
test.
"""

from __future__ import annotations

import json
import threading
import time
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import QSettings, QThread
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QApplication, QHeaderView, QSplitter, QWidget

from intellicrack.core.config import Config
from intellicrack.ui.log_viewer import (
    LogRecordDict,
    LogViewerWindow,
    uninstall_qt_log_handler,
    window as log_viewer_window,
)
from intellicrack.ui.log_viewer._model import LogRecordTableModel
from intellicrack.ui.log_viewer._proxy import LogFilterProxyModel
from intellicrack.ui.log_viewer.window import (
    _EVENT_COLUMN,
    _FILTER_PANEL_MIN_WIDTH,
    _LOCATION_COLUMN,
    _LOGGER_COLUMN,
    GenericCallableWorker,
    _LogTableView,
)


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")

_WAIT_TIMEOUT_MS: Final[int] = 5_000
_WRITE_SLEEP_S: Final[float] = 0.5
_FAST_RETURN_BUDGET_S: Final[float] = 0.25
_LONG_LOGGER_MIN_WIDTH_PX: Final[int] = 300


@pytest.fixture(autouse=True)
def _qsettings_tmp(tmp_path: Path) -> None:
    """Redirect ``QSettings`` ``IniFormat`` storage into ``tmp_path``.

    ``LogViewerWindow._build_settings`` always constructs its
    ``QSettings`` with ``IniFormat``/``UserScope``, so redirecting that
    path is the only way to keep window construction from touching the
    developer's real user profile during a test run.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    QSettings.setPath(
        QSettings.Format.IniFormat,
        QSettings.Scope.UserScope,
        str(tmp_path / "qsettings"),
    )


@pytest.fixture(autouse=True)
def _cleanup_qt_log_handler() -> Generator[None]:
    """Detach the process-global Qt log handler after each test.

    Yields:
        None: Nothing; runs the handler teardown after the test body.
    """
    yield
    uninstall_qt_log_handler()


def _make_config(tmp_path: Path) -> Config:
    """Build a minimal :class:`Config` rooted at ``tmp_path``.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Config: Config with directories pointed at ``tmp_path``.
    """
    cfg = Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    cfg.logs_directory.mkdir(parents=True, exist_ok=True)
    return cfg


def _open_window(qtbot: QtBot, tmp_path: Path) -> LogViewerWindow:
    """Build, register, and show a real :class:`LogViewerWindow`.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.

    Returns:
        LogViewerWindow: The open, shown viewer window.
    """
    config = _make_config(tmp_path)
    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()
    qtbot.waitExposed(window)
    return window


def _record(*, event: str = "evt", level: str = "INFO", logger: str = "intellicrack.tests") -> LogRecordDict:
    """Build a minimal :class:`LogRecordDict` for direct model seeding.

    Args:
        event: Event identifier to set on the record.
        level: Log level name.
        logger: Dotted logger name.

    Returns:
        LogRecordDict: A populated record dictionary.
    """
    return LogRecordDict(
        timestamp="2026-07-02 10:00:00",
        level=level,
        logger=logger,
        module="m",
        function="f",
        line_number=1,
        event=event,
        extras={},
    )


def _seed_model_records(window: LogViewerWindow, count: int) -> None:
    """Append ``count`` records directly to the window's model and flush them.

    Bypasses on-disk seeding and the tail reader entirely so tests get a
    deterministic, immediately-visible row count instead of racing the
    coalescing timer or disk I/O.

    Args:
        window: The open viewer window.
        count: Number of records to append.
    """
    for i in range(count):
        window.model.append_record(_record(event=f"evt_{i}"))
    window.model.flush()


def _trigger_action(window: LogViewerWindow, text: str) -> None:
    """Trigger the toolbar :class:`QAction` whose label equals ``text``.

    Args:
        window: The viewer window.
        text: Exact label text of the desired action.

    Raises:
        AssertionError: When no matching action is present.
    """
    for action in window.findChildren(QAction):
        if action.text() == text:
            action.trigger()
            return
    msg = f"toolbar action not found: {text!r}"
    raise AssertionError(msg)


def _find_splitter(window: LogViewerWindow) -> QSplitter:
    """Locate the single top-level :class:`QSplitter` inside the window.

    Args:
        window: The viewer window to search.

    Returns:
        QSplitter: The splitter dividing the filter panel from the table.
    """
    splitters = window.findChildren(QSplitter)
    assert len(splitters) == 1, f"expected exactly one QSplitter in LogViewerWindow, found {len(splitters)}"
    return splitters[0]


def test_m2_save_all_returns_before_slow_write_completes(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M2: ``_on_save_all`` must return before the write finishes, not block on it.

    Wraps the real ``_write_records_jsonl`` helper so it sleeps for
    ``_WRITE_SLEEP_S`` before performing the actual (real) write. Pre-fix,
    ``_save_records`` ran that serialize+write loop inline in the slot, so
    triggering "Save All As..." would block the calling (GUI) thread for the
    full sleep duration and the file would already exist by the time the
    trigger call returned. Post-fix, the call returns almost immediately and
    the file does not exist yet at that point; it appears only once the
    background worker finishes.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = _open_window(qtbot, tmp_path)
    _seed_model_records(window, count=5)

    target = tmp_path / "save_all_slow.jsonl"
    monkeypatch.setattr(
        "intellicrack.ui.log_viewer.window.QFileDialog.getSaveFileName",
        lambda *_a, **_k: (str(target), "JSON Lines (*.jsonl)"),
    )

    real_write = log_viewer_window._write_records_jsonl

    def _slow_write(path: str, records: list[LogRecordDict]) -> int:
        time.sleep(_WRITE_SLEEP_S)
        return real_write(path, records)

    monkeypatch.setattr("intellicrack.ui.log_viewer.window._write_records_jsonl", _slow_write)

    started = time.perf_counter()
    _trigger_action(window, "Save All As...")
    elapsed = time.perf_counter() - started

    assert elapsed < _FAST_RETURN_BUDGET_S, (
        f"'Save All As...' blocked the GUI thread for {elapsed:.3f}s while _write_records_jsonl "
        f"sleeps {_WRITE_SLEEP_S}s; a call still synchronous on the GUI thread would take at least that long."
    )
    assert not target.exists(), "the file must not exist yet immediately after the (non-blocking) trigger returns"

    qtbot.waitUntil(target.exists, timeout=_WAIT_TIMEOUT_MS)
    saved = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(saved) == 5, f"expected all 5 seeded records to be written by the background worker, got {len(saved)}"
    window.close()


def test_m2_save_all_write_executes_on_background_worker_thread(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M2: the real write must execute on a ``GenericCallableWorker`` thread, not the GUI thread.

    Replaces ``GenericCallableWorker`` in the window module with a
    subclass that records every instance constructed, and wraps
    ``_write_records_jsonl`` to record the identity of the OS thread that
    executes it. Pre-fix neither the module attribute
    ``intellicrack.ui.log_viewer.window.GenericCallableWorker`` nor
    ``intellicrack.ui.log_viewer.window._write_records_jsonl`` existed (the
    write logic was inlined directly in ``_save_records``), so the
    ``monkeypatch.setattr`` calls below would themselves raise
    ``AttributeError``. Post-fix, exactly one real ``QThread``-backed worker
    is constructed and the write runs on a different OS thread than the one
    that triggered the action.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = _open_window(qtbot, tmp_path)
    _seed_model_records(window, count=3)

    target = tmp_path / "save_all_bg.jsonl"
    monkeypatch.setattr(
        "intellicrack.ui.log_viewer.window.QFileDialog.getSaveFileName",
        lambda *_a, **_k: (str(target), "JSON Lines (*.jsonl)"),
    )

    gui_thread_id = threading.get_ident()
    write_thread_ids: list[int] = []
    real_write = log_viewer_window._write_records_jsonl

    def _tracking_write(path: str, records: list[LogRecordDict]) -> int:
        write_thread_ids.append(threading.get_ident())
        return real_write(path, records)

    monkeypatch.setattr("intellicrack.ui.log_viewer.window._write_records_jsonl", _tracking_write)

    created_workers: list[GenericCallableWorker] = []

    class _TrackingWorker(GenericCallableWorker):
        """Subclass of the real worker that records each instance created."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            """Construct the real worker, then record this instance.

            Args:
                *args: Positional arguments forwarded to the real worker.
                **kwargs: Keyword arguments forwarded to the real worker.
            """
            super().__init__(*args, **kwargs)
            created_workers.append(self)

    monkeypatch.setattr("intellicrack.ui.log_viewer.window.GenericCallableWorker", _TrackingWorker)

    _trigger_action(window, "Save All As...")

    qtbot.waitUntil(lambda: bool(write_thread_ids), timeout=_WAIT_TIMEOUT_MS)
    qtbot.waitUntil(target.exists, timeout=_WAIT_TIMEOUT_MS)

    assert len(created_workers) == 1, f"expected exactly one worker to be dispatched, got {len(created_workers)}"
    assert isinstance(created_workers[0], QThread), "_save_records did not dispatch a real QThread-backed worker"
    assert write_thread_ids[0] != gui_thread_id, (
        "_write_records_jsonl executed on the GUI thread instead of the worker's background OS thread"
    )
    window.close()


def test_m40_logger_location_event_columns_use_non_interactive_resize_mode() -> None:
    """M40: Logger/Function:Line/Event columns must not be left at ``Interactive`` mode.

    Pre-fix, the header was set to ``Interactive`` for every section and
    only Time and Level were overridden to ``ResizeToContents``, leaving
    the Logger, Function:Line and Event columns at Qt's fixed ~100px
    default regardless of content. Post-fix, Logger and Function:Line use
    ``ResizeToContents`` and Event uses ``Stretch``.
    """
    proxy = LogFilterProxyModel(parent=None)
    proxy.setSourceModel(LogRecordTableModel(parent=None))
    host = QWidget()
    view = _LogTableView(proxy, host)
    header = view.horizontalHeader()
    assert header is not None

    for column in (_LOGGER_COLUMN, _LOCATION_COLUMN, _EVENT_COLUMN):
        mode = header.sectionResizeMode(column)
        assert mode != QHeaderView.ResizeMode.Interactive, f"column {column} is still left at the narrow Interactive default resize mode"
    assert header.sectionResizeMode(_LOGGER_COLUMN) == QHeaderView.ResizeMode.ResizeToContents
    assert header.sectionResizeMode(_LOCATION_COLUMN) == QHeaderView.ResizeMode.ResizeToContents
    assert header.sectionResizeMode(_EVENT_COLUMN) == QHeaderView.ResizeMode.Stretch
    host.deleteLater()


def test_m40_long_logger_name_widens_column_instead_of_clipping(qtbot: QtBot) -> None:
    """M40: a long, dotted logger name must widen its column rather than being clipped.

    Builds two independent, freshly-populated table views -- one with a
    one-character logger name, one with a long dotted logger name typical
    of Intellicrack's real loggers -- and compares the resulting column
    widths. Pre-fix, ``Interactive`` mode holds every column at a fixed
    default width regardless of content, so both widths would be equal and
    the long name would render clipped to a handful of characters.
    Post-fix, ``ResizeToContents`` grows the Logger column to fit the
    longer content.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    short_host = QWidget()
    short_model = LogRecordTableModel(parent=None)
    short_proxy = LogFilterProxyModel(parent=None)
    short_proxy.setSourceModel(short_model)
    short_view = _LogTableView(short_proxy, short_host)
    qtbot.addWidget(short_host)
    short_model.append_record(_record(logger="a"))
    short_model.flush()
    qtbot.wait(20)
    baseline_width = short_view.columnWidth(_LOGGER_COLUMN)

    long_host = QWidget()
    long_model = LogRecordTableModel(parent=None)
    long_proxy = LogFilterProxyModel(parent=None)
    long_proxy.setSourceModel(long_model)
    long_view = _LogTableView(long_proxy, long_host)
    qtbot.addWidget(long_host)
    long_logger = "intellicrack." * 6 + "log_viewer._tail_reader_component"
    long_model.append_record(_record(logger=long_logger))
    long_model.flush()
    qtbot.wait(20)
    widened_width = long_view.columnWidth(_LOGGER_COLUMN)

    assert widened_width > baseline_width, (
        f"Logger column did not widen for a long logger name (baseline={baseline_width}px, long={widened_width}px)"
    )
    assert widened_width > _LONG_LOGGER_MIN_WIDTH_PX, (
        f"Logger column stayed narrow ({widened_width}px) despite a {len(long_logger)}-character logger name"
    )


def test_l4_splitter_children_not_collapsible(qtbot: QtBot, tmp_path: Path) -> None:
    """L4: the filter/table splitter must disable Qt's default pane-collapsing.

    Pre-fix, the ``QSplitter`` housing the filter panel was constructed
    with no call to ``setChildrenCollapsible``, leaving Qt's default of
    ``True`` in effect -- exactly what permits a drag past the panel's
    natural size to snap it to 0px.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    window = _open_window(qtbot, tmp_path)
    splitter = _find_splitter(window)
    assert splitter.childrenCollapsible() is False
    window.close()


def test_l4_dragging_splitter_to_left_edge_keeps_filter_panel_visible(qtbot: QtBot, tmp_path: Path) -> None:
    """L4: dragging the splitter handle to the left edge must not hide the filter panel.

    ``QSplitter.moveSplitter(0, 1)`` is the same primitive Qt uses when a
    user drags the handle (or double-clicks it) all the way to the left
    edge. Pre-fix (default ``childrenCollapsible=True``, no minimum width
    on the filter panel) this collapsed the panel to 0px, hiding the
    Minimum Level combo, logger regex, text search, Max Rows spin box and
    Auto-scroll checkbox entirely. Post-fix, the enforced minimum width
    keeps the panel at least ``_FILTER_PANEL_MIN_WIDTH`` px wide and
    visible.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    window = _open_window(qtbot, tmp_path)
    splitter = _find_splitter(window)
    filter_panel = splitter.widget(0)
    assert filter_panel is not None

    splitter.moveSplitter(0, 1)
    QApplication.processEvents()

    assert filter_panel.width() >= _FILTER_PANEL_MIN_WIDTH, (
        f"filter panel collapsed to {filter_panel.width()}px after dragging the splitter to the left edge"
    )
    assert filter_panel.isVisible()
    window.close()


def test_l4_filter_panel_has_nonzero_minimum_width(qtbot: QtBot, tmp_path: Path) -> None:
    """L4: the filter panel must carry an explicit, non-trivial minimum width.

    This is the concrete configuration the fix introduces
    (``panel.setMinimumWidth(_FILTER_PANEL_MIN_WIDTH)``); pre-fix the panel
    had no minimum size set at all (``minimumWidth()`` defaults to ``0``),
    which is precisely what let the splitter collapse it to zero.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    window = _open_window(qtbot, tmp_path)
    splitter = _find_splitter(window)
    filter_panel = splitter.widget(0)
    assert filter_panel is not None
    assert filter_panel.minimumWidth() >= _FILTER_PANEL_MIN_WIDTH
    window.close()
