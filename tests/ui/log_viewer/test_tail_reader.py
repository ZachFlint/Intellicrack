# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for :class:`LogFileTailReader`."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.log_viewer import LogFileTailReader


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


def _write_lines(path: Path, *entries: dict[str, object]) -> None:
    """Append JSON-Lines entries to a log file.

    Args:
        path: Target log file.
        *entries: Records to encode as JSON Lines.
    """
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for entry in entries:
            handle.write(json.dumps(entry))
            handle.write("\n")


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
        "line_number": 1,
        "event": event,
        "extras_marker": True,
    }


def test_initial_load_emits_all_lines(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify the initial load fans out every parsed line.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "logs.jsonl"
    _write_lines(log_path, _entry("a"), _entry("b"), _entry("c"))

    reader = LogFileTailReader(log_path)
    received: list[dict[str, object]] = []
    reader.record_emitted.connect(received.append)

    with qtbot.waitSignal(reader.initial_load_complete, timeout=3_000):
        reader.start()
    qtbot.wait(50)
    reader.stop()

    events = [r["event"] for r in received]
    assert events == ["a", "b", "c"]


def test_initial_load_caps_at_max_bytes(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify the initial load only reads the tail of large files.

    Each padding line is 690 bytes.  With 50 padding entries the file
    is 34 860 bytes total.  The 2 048-byte tail window starts at byte
    32 812, which lands inside padding entry 48 (0-indexed).
    ``skip_first_line=True`` drops that partial entry, leaving exactly
    two full padding entries followed by ``recent_1`` and ``recent_2``.
    Any bug that widens the cap (or disables the tail logic entirely)
    must turn this test red.

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
    qtbot.wait(50)
    reader.stop()

    events = [r["event"] for r in received]
    # The 2 048-byte tail window fits exactly 2 full padding entries plus
    # recent_1 and recent_2.  Both recent entries must appear (a regression
    # that skips the first post-cap line would be invisible otherwise), and
    # the tail must end with that exact suffix in the correct order.
    assert events.count("padding") == 2, f"Expected exactly 2 padding entries in the tail, got {events.count('padding')}: {events}"
    assert "recent_1" in events, f"recent_1 missing from tail events: {events}"
    assert "recent_2" in events, f"recent_2 missing from tail events: {events}"
    assert events[-4:] == ["padding", "padding", "recent_1", "recent_2"], f"Tail suffix mismatch: {events[-4:]}"


def test_live_append_via_watcher(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify newly appended lines reach the reader via watcher/poll.

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
    qtbot.wait(50)

    _write_lines(log_path, _entry("b"), _entry("c"))
    reader.force_poll()
    qtbot.wait(100)
    reader.stop()

    events = [r["event"] for r in received]
    assert events[:1] == ["a"]
    assert "b" in events
    assert "c" in events


def test_rotation_emits_synthetic_notice(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify truncation/rotation produces the synthetic notice before new rows.

    The spec requires that the ``log_file_rotated`` synthetic record visually
    brackets the restart: it must appear in the event stream *before* any
    post-rotation records.  ``_read_chunk`` emits the notice synchronously
    (before reading the new content), so a correct implementation always
    delivers the notice first.  If a regression reorders or merges these
    operations the ordering assertion turns this test red.

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
    qtbot.wait(50)

    log_path.write_text("", encoding="utf-8")
    _write_lines(log_path, _entry("after_rotation"))
    reader.force_poll()
    qtbot.wait(100)
    reader.stop()

    events = [r["event"] for r in received]
    assert "log_file_rotated" in events, f"Rotation notice absent from events: {events}"
    assert "after_rotation" in events, f"Post-rotation record absent from events: {events}"
    rotation_idx = events.index("log_file_rotated")
    after_idx = events.index("after_rotation")
    assert rotation_idx < after_idx, (
        f"Rotation notice (index {rotation_idx}) must precede post-rotation record (index {after_idx}); full event list: {events}"
    )


def test_corrupt_lines_skipped(qtbot: QtBot, tmp_path: Path) -> None:
    """Verify malformed JSON lines do not crash the parser.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    log_path = tmp_path / "logs.jsonl"
    with log_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("{not a valid json line}\n")
        handle.write(json.dumps(_entry("good_event")) + "\n")
        handle.write("\n")
        handle.write("garbage\n")

    reader = LogFileTailReader(log_path)
    received: list[dict[str, object]] = []
    reader.record_emitted.connect(received.append)
    with qtbot.waitSignal(reader.initial_load_complete, timeout=3_000):
        reader.start()
    qtbot.wait(50)
    reader.stop()

    events = [r["event"] for r in received]
    assert events == ["good_event"]
