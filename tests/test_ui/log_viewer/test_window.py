# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""End-to-end tests for :class:`LogViewerWindow`."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QSettings, Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QApplication, QMessageBox, QWidget

from intellicrack.core.config import Config
from intellicrack.ui.log_viewer import LogRecordDetailsDialog, LogRecordDict, LogViewerWindow


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp", "qsettings_tmp")


_EXPECTED_RECORDS: int = 4
_EXPECTED_WINDOW_WIDTH: int = 900
_EXPECTED_WINDOW_HEIGHT: int = 500
_DEFAULT_TIMEOUT_MS: int = 3_000
_LIVE_RECORD_TIMEOUT_MS: int = 2_000
_PERSIST_MAX_ROWS: int = 25_000


def _make_config(tmp_path: Path) -> Config:
    """Build a minimal :class:`Config` rooted at ``tmp_path``.

    Args:
        tmp_path: Pytest temp directory.

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


def _seed_log_file(path: Path, count: int = 3) -> None:
    """Seed a JSON-Lines log file with ``count`` records.

    Args:
        path: Target log file.
        count: Number of records to write.
    """
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for i in range(count):
            handle.write(
                json.dumps(
                    {
                        "timestamp": "2026-05-25 10:00:00",
                        "level": "INFO",
                        "logger": "intellicrack.tests",
                        "module": "m",
                        "function": "f",
                        "line_number": i,
                        "event": f"seed_event_{i}",
                    },
                ),
            )
            handle.write("\n")


def _wait_until_rows(qtbot: QtBot, window: LogViewerWindow, count: int, timeout: int = _DEFAULT_TIMEOUT_MS) -> None:
    """Wait until the underlying model has at least ``count`` rows.

    Args:
        qtbot: pytest-qt bot fixture.
        window: Open viewer window.
        count: Minimum number of rows required.
        timeout: Maximum wait in milliseconds.
    """

    def predicate() -> bool:
        return window.model.rowCount() >= count

    qtbot.waitUntil(predicate, timeout=timeout)


def test_window_opens_and_loads_history(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify the window backfills the table from the on-disk log.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    _seed_log_file(config.logs_directory / "intellicrack.log", count=_EXPECTED_RECORDS)

    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()

    _wait_until_rows(qtbot, window, _EXPECTED_RECORDS)
    window.close()


def test_level_filter_narrows_visible_rows(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify changing the level filter restricts proxy rows.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    log_path = config.logs_directory / "intellicrack.log"

    info_payload = {
        "timestamp": "2026-05-25 10:00:00",
        "level": "INFO",
        "logger": "intellicrack.t",
        "module": "m",
        "function": "f",
        "line_number": 1,
        "event": "info_event",
    }
    error_payload = dict(info_payload)
    error_payload["level"] = "ERROR"
    error_payload["event"] = "error_event"
    with log_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(info_payload) + "\n")
        handle.write(json.dumps(error_payload) + "\n")

    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()
    _wait_until_rows(qtbot, window, 2)

    window.set_min_level(logging.ERROR)
    qtbot.waitUntil(lambda: window.proxy.rowCount() == 1, timeout=_LIVE_RECORD_TIMEOUT_MS)
    window.close()


def test_clear_empties_model(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify the public :meth:`LogViewerWindow.clear` empties the model.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    _seed_log_file(config.logs_directory / "intellicrack.log", count=5)
    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()
    _wait_until_rows(qtbot, window, 5)

    window.clear()
    assert window.model.rowCount() == 0
    window.close()


def test_geometry_persists_across_open_close(qtbot: QtBot, tmp_path: Path, qsettings_tmp: None) -> None:
    """Verify closing the window persists its exact geometry to QSettings.

    On close the window must write its current ``saveGeometry()`` blob to the
    user-scope settings so a later instance can restore it. The gate asserts the
    persisted blob equals what the window reported, which is deterministic; the
    re-rendered pixel size of a restored window is not reliable under the
    offscreen Qt platform and so is not asserted here.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
        qsettings_tmp: Redirects QSettings to a per-test temp INI so the
            persisted geometry is isolated from other tests sharing the store.
    """
    del qsettings_tmp
    config = _make_config(tmp_path)
    _seed_log_file(config.logs_directory / "intellicrack.log", count=1)

    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()
    window.resize(_EXPECTED_WINDOW_WIDTH, _EXPECTED_WINDOW_HEIGHT)
    qtbot.wait(50)
    expected_blob = bytes(window.saveGeometry())
    window.close()

    settings = QSettings(
        QSettings.Format.IniFormat,
        QSettings.Scope.UserScope,
        "Intellicrack",
        "LogViewer",
    )
    stored = settings.value("geometry")
    assert stored is not None, "closing the window did not persist geometry to QSettings"
    assert bytes(stored) == expected_blob, "persisted geometry does not match the window's saveGeometry() blob"


def test_pause_resume_toggle(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify the Pause toggle flips the handler's flag.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    _seed_log_file(config.logs_directory / "intellicrack.log", count=0)
    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()

    assert window.is_paused() is False
    pause = window.pause_action
    assert pause is not None
    pause.setChecked(True)
    assert window.is_paused() is True
    pause.setChecked(False)
    assert window.is_paused() is False
    window.close()


def test_details_dialog_shows_full_json(qtbot: QtBot) -> None:
    """Verify the details dialog renders the record as JSON.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    record = LogRecordDict(
        timestamp="2026-05-25 10:00:00",
        level="INFO",
        logger="intellicrack.tests",
        module="m",
        function="f",
        line_number=1,
        event="detail_event",
        extras={"k": "v"},
    )
    dialog = LogRecordDetailsDialog(record)
    qtbot.addWidget(dialog)
    text = dialog.text
    assert '"event": "detail_event"' in text
    assert '"k": "v"' in text


def test_handler_signal_appends_live_record(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify records emitted via the handler reach the viewer's model.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    _seed_log_file(config.logs_directory / "intellicrack.log", count=0)
    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()
    qtbot.wait(50)

    root_logger = logging.getLogger()
    previous_level = root_logger.level
    root_logger.setLevel(logging.DEBUG)
    try:
        logger = logging.getLogger("intellicrack.tests.window")
        initial = window.model.rowCount()
        logger.warning("live_record_from_test")
        qtbot.waitUntil(lambda: window.model.rowCount() > initial, timeout=_LIVE_RECORD_TIMEOUT_MS)
    finally:
        root_logger.setLevel(previous_level)
        window.close()


def _open_window(
    qtbot: QtBot,
    tmp_path: Path,
    *,
    seed_count: int = 0,
) -> tuple[LogViewerWindow, Config]:
    """Build, register, show, and (optionally) seed a viewer window.

    Waits for both the source model and the filter proxy to reach
    ``seed_count`` rows before returning so callers can interact with
    the table without racing the coalesce timer or the proxy's
    ``rowsInserted`` cascade.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
        seed_count: Number of records to seed in the on-disk log.

    Returns:
        tuple[LogViewerWindow, Config]: The open window and its config.
    """
    config = _make_config(tmp_path)
    _seed_log_file(config.logs_directory / "intellicrack.log", count=seed_count)
    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()
    if seed_count > 0:
        _wait_until_rows(qtbot, window, seed_count)
        qtbot.waitUntil(lambda: window.proxy.rowCount() == seed_count, timeout=_DEFAULT_TIMEOUT_MS)
    return window, config


def _trigger_action(window: LogViewerWindow, text: str) -> None:
    """Trigger the toolbar QAction whose label equals ``text``.

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


def test_save_selected_writes_jsonl_to_disk(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the Save Selected action serializes selected rows to JSONL.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window, _ = _open_window(qtbot, tmp_path, seed_count=3)
    target = tmp_path / "saved_selected.jsonl"
    monkeypatch.setattr(
        "intellicrack.ui.log_viewer.window.QFileDialog.getSaveFileName",
        lambda *_a, **_k: (str(target), "JSON Lines (*.jsonl)"),
    )

    table = window._table_view
    assert table is not None
    table.selectAll()
    _trigger_action(window, "Save Selected As...")

    assert target.exists()
    lines = target.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    for line in lines:
        decoded = json.loads(line)
        assert decoded["event"].startswith("seed_event_")
    window.close()


def test_save_selected_no_selection_shows_info(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a Save Selected with no selection shows an informational dialog.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window, _ = _open_window(qtbot, tmp_path, seed_count=2)
    info_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "intellicrack.ui.log_viewer.window.QMessageBox.information",
        lambda _parent, title, message, *_a, **_k: info_calls.append((title, message)) or QMessageBox.StandardButton.Ok,
    )
    saved: list[object] = []
    monkeypatch.setattr(
        "intellicrack.ui.log_viewer.window.QFileDialog.getSaveFileName",
        lambda *_a, **_k: saved.append("called") or ("", ""),
    )

    table = window._table_view
    assert table is not None
    selection = table.selectionModel()
    assert selection is not None
    selection.clearSelection()
    _trigger_action(window, "Save Selected As...")

    assert info_calls
    assert info_calls[0][0] == "Save Selected"
    assert saved == []
    window.close()


def test_save_all_writes_visible_post_filter(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify Save All writes only rows currently visible through the proxy.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    config = _make_config(tmp_path)
    log_path = config.logs_directory / "intellicrack.log"
    payload_info = {
        "timestamp": "2026-05-25 10:00:00",
        "level": "INFO",
        "logger": "intellicrack.t",
        "module": "m",
        "function": "f",
        "line_number": 1,
        "event": "info_event",
    }
    payload_error = dict(payload_info, level="ERROR", event="error_event")
    with log_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload_info) + "\n")
        handle.write(json.dumps(payload_error) + "\n")
    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()
    _wait_until_rows(qtbot, window, 2)
    window.set_min_level(logging.ERROR)
    qtbot.waitUntil(lambda: window.proxy.rowCount() == 1, timeout=_LIVE_RECORD_TIMEOUT_MS)

    target = tmp_path / "visible.jsonl"
    monkeypatch.setattr(
        "intellicrack.ui.log_viewer.window.QFileDialog.getSaveFileName",
        lambda *_a, **_k: (str(target), "JSON Lines (*.jsonl)"),
    )
    _trigger_action(window, "Save All As...")

    saved = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(saved) == 1
    assert saved[0]["event"] == "error_event"
    window.close()


def test_save_records_oserror_routes_to_warning_dialog(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a save-time ``OSError`` is surfaced via QMessageBox.warning.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window, _ = _open_window(qtbot, tmp_path, seed_count=2)
    qtbot.waitUntil(lambda: window.proxy.rowCount() == 2, timeout=_LIVE_RECORD_TIMEOUT_MS)
    target_dir = tmp_path / "target_is_directory"
    target_dir.mkdir()
    monkeypatch.setattr(
        "intellicrack.ui.log_viewer.window.QFileDialog.getSaveFileName",
        lambda *_a, **_k: (str(target_dir), "JSON Lines (*.jsonl)"),
    )
    warning_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "intellicrack.ui.log_viewer.window.QMessageBox.warning",
        lambda _parent, title, message, *_a, **_k: warning_calls.append((title, message)) or QMessageBox.StandardButton.Ok,
    )
    monkeypatch.setattr(
        "intellicrack.ui.log_viewer.window.QMessageBox.information",
        lambda *_a, **_k: QMessageBox.StandardButton.Ok,
    )

    table = window._table_view
    assert table is not None
    table.selectAll()
    qtbot.wait(50)
    _trigger_action(window, "Save Selected As...")

    assert warning_calls
    assert warning_calls[0][0] == "Save Logs"
    assert "Failed to save log records" in warning_calls[0][1]
    window.close()


def test_open_logs_folder_invokes_browser_helper(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the Open Logs Folder action dispatches to the OS file browser.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window, config = _open_window(qtbot, tmp_path, seed_count=1)
    opened: list[Path] = []
    monkeypatch.setattr(
        "intellicrack.ui.log_viewer.window._open_in_file_browser",
        opened.append,
    )
    _trigger_action(window, "Open Logs Folder")
    assert opened == [config.logs_directory]
    window.close()


def test_open_logs_folder_missing_directory_shows_warning(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a missing logs directory routes to a warning dialog.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window, config = _open_window(qtbot, tmp_path, seed_count=0)
    for child in list(config.logs_directory.iterdir()):
        child.unlink()
    config.logs_directory.rmdir()
    warning_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "intellicrack.ui.log_viewer.window.QMessageBox.warning",
        lambda _parent, title, message, *_a, **_k: warning_calls.append((title, message)) or QMessageBox.StandardButton.Ok,
    )
    _trigger_action(window, "Open Logs Folder")
    assert warning_calls
    assert warning_calls[0][0] == "Open Logs Folder"
    window.close()


def test_reload_from_disk_replaces_model_contents(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify Reload from Disk drops current rows and rereads the on-disk tail.

    The assertion counts records whose event name was emitted by
    :func:`_seed_log_file` because the viewer's own internal debug logs
    (e.g. ``log_viewer_initial_load_complete``) may also land in the
    model when ambient logging is enabled, so a strict total count
    would be brittle.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    window, config = _open_window(qtbot, tmp_path, seed_count=2)
    log_path = config.logs_directory / "intellicrack.log"
    _seed_log_file(log_path, count=5)
    _trigger_action(window, "Reload from Disk")

    def seeded_count() -> int:
        return sum(1 for r in window.model.all_records() if r["event"].startswith("seed_event_"))

    qtbot.waitUntil(lambda: seeded_count() == 5, timeout=_DEFAULT_TIMEOUT_MS)
    window.close()


def test_logger_regex_filter_via_widget(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify typing into the logger-regex edit applies the proxy filter.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    log_path = config.logs_directory / "intellicrack.log"
    base = {
        "timestamp": "2026-05-25 10:00:00",
        "level": "INFO",
        "module": "m",
        "function": "f",
        "line_number": 1,
        "event": "evt",
    }
    with log_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(dict(base, logger="intellicrack.core")) + "\n")
        handle.write(json.dumps(dict(base, logger="third_party.lib")) + "\n")
    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()
    _wait_until_rows(qtbot, window, 2)

    edit = window._logger_regex_edit
    assert edit is not None
    edit.clear()
    qtbot.keyClicks(edit, r"^intellicrack\.")
    qtbot.waitUntil(lambda: window.proxy.rowCount() == 1, timeout=_LIVE_RECORD_TIMEOUT_MS)
    assert window.proxy.logger_pattern_source() == r"^intellicrack\."
    window.close()


def test_text_query_filter_via_widget(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify the search edit narrows visible rows by text query.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    log_path = config.logs_directory / "intellicrack.log"
    base = {
        "timestamp": "2026-05-25 10:00:00",
        "level": "INFO",
        "logger": "intellicrack.t",
        "module": "m",
        "function": "f",
        "line_number": 1,
    }
    with log_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(dict(base, event="alpha_event")) + "\n")
        handle.write(json.dumps(dict(base, event="beta_event")) + "\n")
    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()
    _wait_until_rows(qtbot, window, 2)

    text_edit = window._text_query_edit
    assert text_edit is not None
    text_edit.clear()
    qtbot.keyClicks(text_edit, "alpha")
    qtbot.waitUntil(lambda: window.proxy.rowCount() == 1, timeout=_LIVE_RECORD_TIMEOUT_MS)
    window.close()


def test_case_sensitive_checkbox_toggles_proxy(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify clicking the Case-sensitive checkbox flips the proxy mode.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    window, _ = _open_window(qtbot, tmp_path, seed_count=1)
    check = window._case_check
    assert check is not None
    assert check.isChecked() is False
    qtbot.mouseClick(check, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(check.isChecked, timeout=_DEFAULT_TIMEOUT_MS)
    text_edit = window._text_query_edit
    assert text_edit is not None
    text_edit.clear()
    qtbot.keyClicks(text_edit, "SEED_EVENT_0")
    qtbot.waitUntil(lambda: window.proxy.rowCount() == 0, timeout=_DEFAULT_TIMEOUT_MS)
    window.close()


def test_max_rows_spin_box_resizes_model(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify changing the Max Rows spin box reconfigures the model cap.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    window, _ = _open_window(qtbot, tmp_path, seed_count=0)
    spin = window._max_rows_spin
    assert spin is not None
    spin.setValue(_PERSIST_MAX_ROWS)
    qtbot.waitUntil(lambda: window.model.max_rows == _PERSIST_MAX_ROWS, timeout=_LIVE_RECORD_TIMEOUT_MS)
    window.close()


def test_auto_scroll_default_scrolls_to_bottom(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify auto-scroll triggers ``scrollToBottom`` on row insertion.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
        monkeypatch: Pytest monkeypatch fixture used to spy on
            ``scrollToBottom`` calls.
    """
    window, _ = _open_window(qtbot, tmp_path, seed_count=0)
    table = window._table_view
    assert table is not None
    calls: list[int] = []
    monkeypatch.setattr(table, "scrollToBottom", lambda: calls.append(1))
    window.model.append_record(
        {
            "timestamp": "2026-05-25 10:00:00",
            "level": "INFO",
            "logger": "intellicrack.t",
            "module": "m",
            "function": "f",
            "line_number": 1,
            "event": "fresh",
            "extras": {},
        },
    )
    window.model.flush()
    qtbot.waitUntil(lambda: bool(calls), timeout=_LIVE_RECORD_TIMEOUT_MS)
    window.close()


def test_auto_scroll_disabled_does_not_scroll(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify turning off auto-scroll suppresses ``scrollToBottom`` calls.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window, _ = _open_window(qtbot, tmp_path, seed_count=0)
    check = window._auto_scroll_check
    assert check is not None
    qtbot.mouseClick(check, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: not check.isChecked(), timeout=_LIVE_RECORD_TIMEOUT_MS)

    table = window._table_view
    assert table is not None
    calls: list[int] = []
    monkeypatch.setattr(table, "scrollToBottom", lambda: calls.append(1))
    window.model.append_record(
        {
            "timestamp": "2026-05-25 10:00:00",
            "level": "INFO",
            "logger": "intellicrack.t",
            "module": "m",
            "function": "f",
            "line_number": 1,
            "event": "fresh",
            "extras": {},
        },
    )
    window.model.flush()
    qtbot.wait(120)
    assert calls == []
    window.close()


def test_status_bar_counters_track_visible_and_total(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify the ``X visible / Y total`` status label tracks filter changes.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    log_path = config.logs_directory / "intellicrack.log"
    base = {
        "timestamp": "2026-05-25 10:00:00",
        "logger": "intellicrack.t",
        "module": "m",
        "function": "f",
        "line_number": 1,
        "event": "evt",
    }
    with log_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(dict(base, level="INFO")) + "\n")
        handle.write(json.dumps(dict(base, level="WARNING")) + "\n")
        handle.write(json.dumps(dict(base, level="ERROR")) + "\n")
    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()
    _wait_until_rows(qtbot, window, 3)
    label = window._status_counts_label
    assert label is not None

    def label_reflects_counts() -> bool:
        expected = f"{window.proxy.rowCount()} visible / {window.model.rowCount()} total"
        return label.text() == expected

    qtbot.waitUntil(label_reflects_counts, timeout=_LIVE_RECORD_TIMEOUT_MS)
    initial_visible = window.proxy.rowCount()
    assert initial_visible >= 3

    window.set_min_level(logging.ERROR)
    qtbot.waitUntil(lambda: window.proxy.rowCount() < initial_visible, timeout=_LIVE_RECORD_TIMEOUT_MS)
    qtbot.waitUntil(label_reflects_counts, timeout=_LIVE_RECORD_TIMEOUT_MS)
    window.close()


def test_details_dialog_copy_button_pushes_to_clipboard(qtbot: QtBot) -> None:
    """Verify the Copy button in the details dialog writes JSON to the clipboard.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    record = LogRecordDict(
        timestamp="2026-05-25 10:00:00",
        level="INFO",
        logger="intellicrack.tests",
        module="m",
        function="f",
        line_number=1,
        event="clipboard_event",
        extras={"x": 1},
    )
    dialog = LogRecordDetailsDialog(record)
    qtbot.addWidget(dialog)
    clipboard = QApplication.clipboard()
    assert clipboard is not None
    clipboard.clear()
    dialog._on_copy()
    text = clipboard.text()
    assert '"event": "clipboard_event"' in text
    assert '"x": 1' in text


def test_double_click_opens_details_dialog(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify double-clicking a row constructs and shows the details dialog.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
        monkeypatch: Pytest monkeypatch fixture replacing the dialog's
            blocking ``exec`` with an immediate return.
    """
    window, _ = _open_window(qtbot, tmp_path, seed_count=1)
    table = window._table_view
    assert table is not None
    seen: list[LogRecordDict] = []
    original_init = LogRecordDetailsDialog.__init__

    def capturing_init(
        self: LogRecordDetailsDialog,
        record: LogRecordDict,
        parent: QWidget | None = None,
    ) -> None:
        seen.append(record)
        original_init(self, record, parent)

    monkeypatch.setattr(LogRecordDetailsDialog, "__init__", capturing_init)
    monkeypatch.setattr(LogRecordDetailsDialog, "exec", lambda _self: 0)

    proxy_index = table.model().index(0, 0)
    table.doubleClicked.emit(proxy_index)
    qtbot.waitUntil(lambda: bool(seen), timeout=_LIVE_RECORD_TIMEOUT_MS)
    assert seen[0]["event"].startswith("seed_event_")
    window.close()


def test_filter_state_persists_across_open_close(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify filter widget state round-trips through QSettings.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    _seed_log_file(config.logs_directory / "intellicrack.log", count=1)

    first = LogViewerWindow(config)
    qtbot.addWidget(first)
    first.show()
    _wait_until_rows(qtbot, first, 1)
    level_combo = first._level_combo
    logger_edit = first._logger_regex_edit
    text_edit = first._text_query_edit
    case_check = first._case_check
    spin = first._max_rows_spin
    auto_check = first._auto_scroll_check
    assert level_combo is not None
    assert logger_edit is not None
    assert text_edit is not None
    assert case_check is not None
    assert spin is not None
    assert auto_check is not None

    level_combo.setCurrentText("ERROR")
    logger_edit.setText(r"^intellicrack\.")
    text_edit.setText("needle")
    case_check.setChecked(True)
    spin.setValue(_PERSIST_MAX_ROWS)
    auto_check.setChecked(False)
    qtbot.wait(50)
    first.close()

    second = LogViewerWindow(config)
    qtbot.addWidget(second)
    second.show()
    qtbot.wait(100)
    assert second._level_combo is not None
    assert second._level_combo.currentText() == "ERROR"
    assert second._logger_regex_edit is not None
    assert second._logger_regex_edit.text() == r"^intellicrack\."
    assert second._text_query_edit is not None
    assert second._text_query_edit.text() == "needle"
    assert second._case_check is not None
    assert second._case_check.isChecked() is True
    assert second._max_rows_spin is not None
    assert second._max_rows_spin.value() == _PERSIST_MAX_ROWS
    assert second._auto_scroll_check is not None
    assert second._auto_scroll_check.isChecked() is False
    second.close()
