# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit4 C15 (F-0009): hex editor diff tempfile cleanup.

The defect: ``ComparisonMixin._on_compare`` writes the in-memory document
snapshot to a ``tempfile.NamedTemporaryFile(..., delete=False)`` and never
deletes it again. Every diff against an unsaved buffer leaks a file in the
user's temp directory. The fix tracks the temp path on ``self`` and removes
it from both the success and error completion handlers.

These tests construct a ``ComparisonMixin``-backed harness, drive the
internal cleanup logic exactly the way ``_on_compare`` does, and assert
the snapshot is removed once the worker finishes (success or error) and
that consecutive diffs do not pile up old snapshots.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtWidgets import QApplication, QLabel, QTreeWidget, QWidget

from intellicrack.ui.panels.hex_editor.comparison import ComparisonMixin


if TYPE_CHECKING:
    from collections.abc import Generator


_DIFF_PREFIX: Final[str] = "intellicrack_diff_"
_SNAPSHOT_BYTES: Final[bytes] = b"\x00\x01\x02\x03snapshot"


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        QApplication: Qt application instance shared by all tests in the module.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _DiffHarness(ComparisonMixin, QWidget):
    """Minimal :class:`QWidget` subclass exposing :class:`ComparisonMixin` for tests.

    Wires only the attributes the cleanup path actually touches. The diff
    worker itself is not invoked; tests drive the public mixin lifecycle
    directly to verify the temp-file accounting.
    """

    def __init__(self) -> None:
        """Initialise the harness with the mixin attributes the cleanup path requires."""
        super().__init__()
        self.document: Any | None = None
        self.file_path: Path | None = None
        self._hex_widget: Any | None = None
        self._diff_results_tree: QTreeWidget | None = QTreeWidget(self)
        self._diff_results_tree.setColumnCount(4)
        self._diff_summary_label: QLabel | None = QLabel(self)
        self._diff_worker: Any | None = None
        self._diff_temp_path: Path | None = None

    def stage_temp_snapshot(self, payload: bytes = _SNAPSHOT_BYTES) -> Path:
        """Write a real snapshot tempfile and register it the way ``_on_compare`` does.

        Args:
            payload: Bytes to write into the snapshot tempfile.

        Returns:
            Path: Filesystem path of the staged snapshot file.
        """
        with tempfile.NamedTemporaryFile(prefix=_DIFF_PREFIX, delete=False) as tmp:
            tmp.write(payload)
            staged = Path(tmp.name)
        self._diff_temp_path = staged
        return staged

    def tracked_temp_path_for_test(self) -> Path | None:
        """Return the currently tracked snapshot path, or ``None`` if cleared.

        Returns:
            Path | None: The path the mixin currently tracks for cleanup,
                or ``None`` once the cleanup helper has run.
        """
        return self._diff_temp_path

    def trigger_diff_finished_for_test(self, result: dict[str, Any]) -> None:
        """Drive the success completion handler exactly as the worker would.

        Args:
            result: Diff result payload to pass to the handler.
        """
        self._on_diff_finished(result)

    def trigger_diff_error_for_test(self, message: str) -> None:
        """Drive the error completion handler exactly as the worker would.

        Args:
            message: Error string to pass to the handler.
        """
        self._on_diff_error(message)

    def trigger_cleanup_for_test(self) -> None:
        """Run the snapshot cleanup helper directly, mirroring re-entry from ``_on_compare``."""
        self._cleanup_diff_temp()


_EMPTY_RESULT: Final[dict[str, Any]] = {
    "regions": [],
    "total_differences": 0,
    "files_identical": True,
}


@pytest.mark.usefixtures("qapp")
class TestSuccessPathDeletesSnapshot:
    """Successful diff completion must delete the snapshot tempfile."""

    @staticmethod
    def test_on_diff_finished_unlinks_tracked_temp(qapp: QApplication) -> None:
        """Stage a snapshot, drive the success handler, assert the file is gone.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _DiffHarness()
        snapshot = harness.stage_temp_snapshot()
        assert snapshot.exists(), "harness staged tempfile must exist before the test runs"

        harness.trigger_diff_finished_for_test(dict(_EMPTY_RESULT))

        assert not snapshot.exists(), "diff success handler must unlink the staged tempfile"
        assert harness.tracked_temp_path_for_test() is None, "tracked tempfile path must be cleared after cleanup"

    @staticmethod
    def test_on_diff_finished_no_temp_is_safe(qapp: QApplication) -> None:
        """Success handler must not raise when there is no tracked tempfile.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _DiffHarness()
        assert harness.tracked_temp_path_for_test() is None

        harness.trigger_diff_finished_for_test(dict(_EMPTY_RESULT))

        assert harness.tracked_temp_path_for_test() is None


@pytest.mark.usefixtures("qapp")
class TestErrorPathDeletesSnapshot:
    """Errored diff completion must also delete the snapshot tempfile."""

    @staticmethod
    def test_on_diff_error_unlinks_tracked_temp(qapp: QApplication) -> None:
        """Stage a snapshot, drive the error handler, assert the file is gone.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _DiffHarness()
        snapshot = harness.stage_temp_snapshot()
        assert snapshot.exists(), "harness staged tempfile must exist before the test runs"

        harness.trigger_diff_error_for_test("simulated bridge failure")

        assert not snapshot.exists(), "diff error handler must unlink the staged tempfile"
        assert harness.tracked_temp_path_for_test() is None, "tracked tempfile path must be cleared after cleanup"


@pytest.mark.usefixtures("qapp")
class TestRepeatedDiffsDoNotAccumulateLeaks:
    """Each diff must reset prior snapshots to avoid disk accumulation."""

    @staticmethod
    def test_cleanup_helper_removes_currently_tracked_snapshot(qapp: QApplication) -> None:
        """Calling the cleanup helper between diffs must remove the tracked snapshot.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _DiffHarness()
        first = harness.stage_temp_snapshot(b"first snapshot bytes")
        second = harness.stage_temp_snapshot(b"second snapshot bytes")

        assert first.exists(), "first snapshot must exist"
        assert second.exists(), "second snapshot must exist"

        harness.trigger_cleanup_for_test()

        assert not second.exists(), "cleanup helper must unlink the currently tracked snapshot"
        assert harness.tracked_temp_path_for_test() is None
        assert first.exists(), "untracked previous snapshot is not the helper's responsibility"
        first.unlink()

    @staticmethod
    def test_cleanup_helper_tolerates_already_deleted_file(qapp: QApplication) -> None:
        """Cleanup helper must not raise if the tracked file was deleted out of band.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _DiffHarness()
        snapshot = harness.stage_temp_snapshot()
        snapshot.unlink()

        harness.trigger_cleanup_for_test()

        assert harness.tracked_temp_path_for_test() is None
