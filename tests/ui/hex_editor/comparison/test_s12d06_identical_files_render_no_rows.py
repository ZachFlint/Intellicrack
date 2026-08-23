# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression test for defect S12-D06 (A2): spurious row on identical files.

The defect: ``_on_diff_finished`` computed ``diff_region_rows(regions)``
unconditionally and populated the results tree from it regardless of the
``files_identical`` flag returned by the engine. ``diff_region_rows`` only
drops a region whose ``diff_type`` string equals ``MATCH_DIFF_TYPE``
("match"); any whole-file region that arrived with a differently-serialized
diff type would render as a spurious row even though the "Files are
identical" banner was correct.

This test drives the real ``HexEditorBridge.compare_files`` path (real temp
files, real ``intellicrack_hexcore`` native module) over two genuinely
identical byte buffers, feeds the resulting dict into the panel's real
completion handler, and asserts both halves of the contract agree: the
summary banner reads "Files are identical" and the results tree carries zero
top-level rows.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtWidgets import QApplication, QLabel, QTreeWidget, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.comparison import ComparisonMixin


if TYPE_CHECKING:
    from collections.abc import Coroutine, Generator
    from pathlib import Path


pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required to produce a real diff result",
)

_IDENTICAL_PAYLOAD: Final[bytes] = bytes(range(256)) * 4


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
    """
    loop: asyncio.AbstractEventLoop
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        QApplication: Qt application instance shared by all tests in the
            module.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _DiffHarness(ComparisonMixin, QWidget):
    """Minimal widget exposing the mixin's diff-completion path."""

    def __init__(self) -> None:
        """Wire only the attributes the completion path touches."""
        super().__init__()
        self.document: Any | None = None
        self.file_path: Path | None = None
        self._hex_widget: Any | None = None
        self._diff_results_tree: QTreeWidget | None = QTreeWidget(self)
        self._diff_results_tree.setColumnCount(4)
        self._diff_summary_label: QLabel | None = QLabel(self)
        self._diff_worker: Any | None = None
        self._diff_temp_path: Path | None = None

    def render_result(self, result: dict[str, Any]) -> None:
        """Drive the success completion handler exactly as the worker would.

        Args:
            result: Diff result payload to render.
        """
        self._on_diff_finished(result)

    def row_count(self) -> int:
        """Return the number of top-level rows currently in the results tree.

        Returns:
            int: Top-level item count.
        """
        tree = self._diff_results_tree
        assert tree is not None
        return tree.topLevelItemCount()

    def summary_text(self) -> str:
        """Return the caption the panel rendered.

        Returns:
            str: Current summary label text.
        """
        label = self._diff_summary_label
        assert label is not None
        return label.text()


@pytest.fixture
def bridge() -> HexEditorBridge:
    """Create and initialize a real ``HexEditorBridge``.

    Returns:
        HexEditorBridge: An initialized bridge backed by the real hexcore
            native module.
    """
    b = HexEditorBridge()
    _run(b.initialize())
    return b


def test_identical_files_render_zero_rows_through_the_real_bridge(
    qapp: QApplication,
    bridge: HexEditorBridge,
    tmp_path: Path,
) -> None:
    """Comparing two genuinely identical files must render no rows at all.

    The engine's diff over two identical buffers reports ``files_identical``
    together with a single whole-file ``match`` region; the panel must not
    turn that region into a visible row just because the underlying engine
    happened to also enumerate it.

    Args:
        qapp: Qt application fixture (kept alive for widget construction).
        bridge: A real, initialized HexEditorBridge.
        tmp_path: Pytest temporary directory.
    """
    _ = qapp
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    file_a.write_bytes(_IDENTICAL_PAYLOAD)
    file_b.write_bytes(_IDENTICAL_PAYLOAD)

    result = _run(bridge.compare_files(str(file_a), str(file_b)))

    assert result["files_identical"] is True, "fixture must actually produce an identical-files result"
    assert result["regions"], "engine must report at least the whole-file match region, or this gate proves nothing"

    harness = _DiffHarness()
    harness.render_result(result)

    assert harness.summary_text() == "Files are identical"
    assert harness.row_count() == 0


def test_identical_result_renders_no_rows_even_if_the_region_type_string_drifts(
    qapp: QApplication,
    bridge: HexEditorBridge,
    tmp_path: Path,
) -> None:
    """Row rendering must key off ``files_identical``, never off the region's type string.

    Today's engine always tags the whole-file region of an identical result as
    literally ``"match"``, so the row filter alone happens to hide it. If the
    native layer ever serializes that type differently (a renamed variant, a
    different case), the tree must still show zero rows because the file
    comparison as a whole is identical -- that fact must not depend on a
    string spelling elsewhere in the payload staying frozen forever.

    This drives one genuine identical-files comparison through the real
    bridge, then re-renders that same real result with only the region's
    ``diff_type`` field swapped for a value the row filter has never seen, to
    prove the tree is driven by the ``files_identical`` flag rather than by
    successfully recognizing every region as a match.

    Args:
        qapp: Qt application fixture (kept alive for widget construction).
        bridge: A real, initialized HexEditorBridge.
        tmp_path: Pytest temporary directory.
    """
    _ = qapp
    file_a = tmp_path / "c.bin"
    file_b = tmp_path / "d.bin"
    file_a.write_bytes(_IDENTICAL_PAYLOAD)
    file_b.write_bytes(_IDENTICAL_PAYLOAD)

    result = _run(bridge.compare_files(str(file_a), str(file_b)))
    assert result["files_identical"] is True, "fixture must actually produce an identical-files result"
    assert result["regions"], "engine must report at least the whole-file match region, or this gate proves nothing"

    drifted: dict[str, Any] = dict(result)
    drifted["regions"] = [{**region, "diff_type": "unchanged"} for region in result["regions"]]

    harness = _DiffHarness()
    harness.render_result(drifted)

    assert harness.summary_text() == "Files are identical"
    assert harness.row_count() == 0, "a files_identical result must render no rows regardless of the region type spelling"
