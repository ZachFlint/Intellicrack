# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for :class:`LogFileTailReader`.

Every case drives the real reader over real on-disk JSON-Lines files.
Writes are flushed and ``os.fsync``-ed before the reader is polled so the
reader is guaranteed to observe the bytes the test wrote, and the test
synchronises on explicit conditions (``waitSignal`` / ``waitUntil``) rather
than fixed sleeps so a slow machine never produces a spurious pass or fail.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.log_viewer import LogFileTailReader


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


def _write_lines(path: Path, *entries: dict[str, object]) -> None:
    """Append JSON-Lines entries to a log file and force them to disk.

    The handle is flushed and ``os.fsync``-ed before returning so a reader
    that opens the file immediately afterwards observes every byte written
    here, eliminating buffering-related non-determinism.

    Args:
        path: Target log file.
        *entries: Records to encode as JSON Lines.
    """
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for entry in entries:
            handle.write(json.dumps(entry))
            handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _entry(event: str, level: str = "INFO") -> dict[str, object]:
    """Build a structlog-style payload.

    Args:
        event: Event identifier.
        level: Log level.

    Returns:
        dict[str, object]: JSON-serializable record.
    """
    return {
        "timestamp": "2026-05-25 10:00:00",
        "level": level,
        "logger": "intellicrack.tests",
        "module": "m",
        "function": "f",
        "line_number": 7,
        "event": event,
        "extras_marker": True,
    }


def test_initial_load_emits_all_lines_in_order(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify the initial load fans out every parsed line in file order with full fields.

    The expected event sequence is the exact order written to disk, and each
    received record is asserted field-by-field against the known payload so a
    regression that reorders, drops, or mis-parses a field is caught.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "logs.jsonl"
    _write_lines(log_path, _entry("alpha"), _entry("bravo", level="WARNING"), _entry("charlie"))

    reader = LogFileTailReader(log_path)
    received: list[dict[str, object]] = []
    reader.record_emitted.connect(received.append)

    with qtbot.waitSignal(reader.initial_load_complete, timeout=3_000):
        reader.start()
    qtbot.waitUntil(lambda: len(received) == 3, timeout=3_000)
    reader.stop()

    assert [r["event"] for r in received] == ["alpha", "bravo", "charlie"]
    first = received[0]
    assert first["level"] == "INFO"
    assert first["logger"] == "intellicrack.tests"
    assert first["module"] == "m"
    assert first["function"] == "f"
    assert first["line_number"] == 7
    assert received[1]["level"] == "WARNING"
    extras = first["extras"]
    assert isinstance(extras, dict)
    assert extras == {"extras_marker": True}


def test_initial_load_caps_at_max_bytes(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify the initial load only reads the tail of files larger than the cap.

    The file is padded well past the 2 KiB cap, then the two most recent
    records are appended. The reader must surface the most recent record but
    must not replay all 50 padding rows; with a 2 KiB cap over ~500-byte
    padding rows at most a handful of padding rows fit in the window.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "logs.jsonl"
    padding_entry = _entry("padding")
    padding_entry["pad"] = "x" * 500
    for _ in range(50):
        _write_lines(log_path, padding_entry)
    _write_lines(log_path, _entry("recent_1"), _entry("recent_2"))

    reader = LogFileTailReader(log_path, max_initial_bytes=2_048)
    received: list[dict[str, object]] = []
    reader.record_emitted.connect(received.append)

    with qtbot.waitSignal(reader.initial_load_complete, timeout=3_000):
        reader.start()
    qtbot.waitUntil(lambda: any(r["event"] == "recent_2" for r in received), timeout=3_000)
    reader.stop()

    events = [r["event"] for r in received]
    assert events[-1] == "recent_2"
    assert "recent_1" in events
    assert events.count("padding") <= 5
    padding_byte_budget = 2_048
    assert events.count("padding") * 500 <= padding_byte_budget


def test_live_append_via_force_poll_emits_only_new_lines(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify an incremental poll emits exactly the newly appended lines, once each.

    After the historical backfill of ``a``, two new lines are written and a
    poll is forced. The reader must emit ``b`` and ``c`` exactly once and must
    not re-emit the already-loaded ``a`` (no duplicate from re-reading the
    file head).

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "logs.jsonl"
    _write_lines(log_path, _entry("a"))

    reader = LogFileTailReader(log_path)
    received: list[dict[str, object]] = []
    reader.record_emitted.connect(received.append)
    with qtbot.waitSignal(reader.initial_load_complete, timeout=3_000):
        reader.start()
    qtbot.waitUntil(lambda: [r["event"] for r in received] == ["a"], timeout=3_000)

    _write_lines(log_path, _entry("b"), _entry("c"))
    reader.force_poll()
    qtbot.waitUntil(lambda: len(received) == 3, timeout=3_000)
    reader.stop()

    assert [r["event"] for r in received] == ["a", "b", "c"]


def test_rotation_emits_synthetic_notice_then_new_rows(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify a truncation/rotation produces the synthetic notice ahead of new rows.

    Truncating the file to zero then writing a new record must make the reader
    detect the shrink, emit the ``log_file_rotated`` synthetic notice (with the
    rotated path in its extras), and then emit the post-rotation record. The
    notice must precede the new row in the emission order.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "logs.jsonl"
    _write_lines(log_path, _entry("first"), _entry("second"))

    reader = LogFileTailReader(log_path)
    received: list[dict[str, object]] = []
    reader.record_emitted.connect(received.append)
    with qtbot.waitSignal(reader.initial_load_complete, timeout=3_000):
        reader.start()
    qtbot.waitUntil(lambda: len(received) == 2, timeout=3_000)

    with log_path.open("w", encoding="utf-8") as handle:
        handle.flush()
        os.fsync(handle.fileno())
    _write_lines(log_path, _entry("after_rotation"))
    reader.force_poll()
    qtbot.waitUntil(lambda: any(r["event"] == "after_rotation" for r in received), timeout=3_000)
    reader.stop()

    events = [r["event"] for r in received]
    assert events[:2] == ["first", "second"]
    assert "log_file_rotated" in events
    assert "after_rotation" in events
    notice_index = events.index("log_file_rotated")
    assert events.index("after_rotation") > notice_index
    notice = received[notice_index]
    assert notice["level"] == "WARNING"
    notice_extras = notice["extras"]
    assert isinstance(notice_extras, dict)
    assert notice_extras["path"] == str(log_path)


def test_corrupt_and_blank_lines_skipped_valid_preserved(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify malformed, blank, and non-object JSON lines are skipped, valid kept.

    The file deliberately mixes an invalid JSON object literal, a JSON array
    (valid JSON but not an object), a blank line, and raw garbage around one
    well-formed record. Only the single valid structured record may be emitted,
    proving the parser is robust to adversarial/partial log content.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "logs.jsonl"
    with log_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("{not a valid json line}\n")
        handle.write("[1, 2, 3]\n")
        handle.write(json.dumps(_entry("good_event")) + "\n")
        handle.write("\n")
        handle.write("garbage\n")
        handle.flush()
        os.fsync(handle.fileno())

    reader = LogFileTailReader(log_path)
    received: list[dict[str, object]] = []
    reader.record_emitted.connect(received.append)
    with qtbot.waitSignal(reader.initial_load_complete, timeout=3_000):
        reader.start()
    qtbot.waitUntil(lambda: any(r["event"] == "good_event" for r in received), timeout=3_000)
    reader.stop()

    assert [r["event"] for r in received] == ["good_event"]


def test_missing_file_loads_empty_then_picks_up_first_write(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify a reader started on a not-yet-existing file emits nothing then tails it.

    This is the boundary case where ``start`` runs before the log file is
    created. The historical load must complete with zero records and no crash;
    after the file is created and a record appended, a forced poll must surface
    that first record.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "not_yet.jsonl"
    assert not log_path.exists()

    reader = LogFileTailReader(log_path)
    received: list[dict[str, object]] = []
    reader.record_emitted.connect(received.append)
    with qtbot.waitSignal(reader.initial_load_complete, timeout=3_000):
        reader.start()
    assert received == []

    _write_lines(log_path, _entry("first_after_create"))
    reader.force_poll()
    qtbot.waitUntil(lambda: len(received) == 1, timeout=3_000)
    reader.stop()

    assert [r["event"] for r in received] == ["first_after_create"]
