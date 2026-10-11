# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the file comparison tab of the hex editor panel.

Every test drives ``ComparisonMixin`` through a small concrete widget host with real objects: a genuine ``intellicrack_hexcore.HexDocument``,
a real ``HexEditorWidget``, a real ``HexEditorBridge``, the real Qt controls built by ``_create_comparison_tab`` and the real asynchronous
worker the Compare button starts. The files being compared are written under ``tmp_path``, and every expected value (differing byte count,
first differing offset, region count, file sizes) is computed here from the two byte strings rather than read back from the code under test.
"""

from __future__ import annotations

import asyncio
import tempfile
import threading
import types
from typing import TYPE_CHECKING, Any

import intellicrack_hexcore
import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFileDialog, QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.async_bridge import (
    GenericCallableWorker,
    drain_bridge_workers,
    drain_bridge_workers_for,
    run_callable_async,
)
from intellicrack.ui.panels.hex_editor.comparison import ComparisonMixin, execute_diff
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_HEAD: bytes = b"\x00" * 16
_TAIL: bytes = b"\x00" * 16
_DATA_A: bytes = _HEAD + b"\xaa" * 8 + _TAIL
_DATA_B: bytes = _HEAD + b"\xbb" * 8 + _TAIL
_UNRELATED: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
_COMPUTING: str = "Computing diff..."
_COMPARE_CAPTION: str = "Compare With..."
_SNAPSHOT_PREFIX: str = "intellicrack_diff_"
_WAIT_MS: int = 20_000


class _ComparisonHost(ComparisonMixin, QWidget):
    """Concrete widget host that exposes the comparison mixin's slots to the tests."""

    _bridge: HexEditorBridge | None

    def __init__(
        self,
        document: object | None,
        bridge: HexEditorBridge | None,
        hex_widget: object | None = None,
    ) -> None:
        """Create a host with no comparison tab built yet.

        Args:
            document: Document the comparison reads, or ``None``.
            bridge: Hex editor bridge the diff runs through, or ``None``.
            hex_widget: Widget that navigation requests are forwarded to.
        """
        super().__init__()
        self.document = document
        self.file_path = None
        self._hex_widget = hex_widget
        self._bridge = bridge
        self._diff_results_tree = None
        self._diff_summary_label = None
        self._diff_worker = None
        self._diff_temp_path = None

    def build_tab(self) -> QWidget:
        """Build the real comparison tab and place it inside the host.

        Returns:
            QWidget: The tab container created by the mixin.
        """
        container = self._create_comparison_tab()
        QVBoxLayout(self).addWidget(container)
        return container

    def button(self, text: str) -> QPushButton:
        """Find a tab button by its caption.

        Args:
            text: Caption of the wanted button.

        Returns:
            QPushButton: The matching button.

        Raises:
            LookupError: If no button has that caption.
        """
        for candidate in self.findChildren(QPushButton):
            if candidate.text() == text:
                return candidate
        msg = f"no button captioned {text!r}"
        raise LookupError(msg)

    @property
    def tree(self) -> QTreeWidget:
        """The results tree created by the tab.

        Returns:
            QTreeWidget: The tree widget.
        """
        tree = self._diff_results_tree
        assert tree is not None
        return tree

    @property
    def label(self) -> QLabel:
        """The summary label created by the tab.

        Returns:
            QLabel: The summary label.
        """
        label = self._diff_summary_label
        assert label is not None
        return label

    @property
    def worker(self) -> GenericCallableWorker | None:
        """The worker the Compare slot started most recently.

        Returns:
            GenericCallableWorker | None: The worker, or ``None`` when nothing has run.
        """
        return self._diff_worker

    @property
    def temp_path(self) -> Path | None:
        """The snapshot tempfile the mixin currently tracks.

        Returns:
            Path | None: The tracked path, or ``None`` when no snapshot exists.
        """
        return self._diff_temp_path

    @property
    def navigation_target(self) -> object | None:
        """The object navigation requests are forwarded to.

        Returns:
            object | None: The hex widget the host was given.
        """
        return self._hex_widget

    def summary(self) -> str:
        """Return the caption currently shown by the summary label.

        Returns:
            str: Current summary text.
        """
        return self.label.text()

    def rows(self) -> list[tuple[str, str, str, str]]:
        """Return the four visible cells of every top-level row.

        Returns:
            list[tuple[str, str, str, str]]: Offset, length, type and details text per row.
        """
        tree = self.tree
        collected: list[tuple[str, str, str, str]] = []
        for index in range(tree.topLevelItemCount()):
            item = tree.topLevelItem(index)
            assert item is not None
            collected.append((item.text(0), item.text(1), item.text(2), item.text(3)))
        return collected

    def row_item(self, index: int) -> QTreeWidgetItem:
        """Return one rendered row.

        Args:
            index: Index of the top-level row.

        Returns:
            QTreeWidgetItem: The row at that index.
        """
        item = self.tree.topLevelItem(index)
        assert item is not None
        return item

    def adopt_worker(self, worker: GenericCallableWorker) -> None:
        """Record a worker as the host's current diff worker.

        Args:
            worker: The worker to record.
        """
        self._diff_worker = worker

    def adopt_temp_path(self, path: Path) -> None:
        """Record a path as the snapshot tempfile the mixin must clean up.

        Args:
            path: Path the mixin should treat as its snapshot.
        """
        self._diff_temp_path = path

    def use_bridge(self, bridge: HexEditorBridge | None) -> None:
        """Install the bridge the diff runs through.

        Args:
            bridge: The bridge, or ``None`` to make the panel report it as unavailable.
        """
        self._bridge = bridge

    def drop_tree(self) -> None:
        """Forget the results tree so the handlers see it as not yet created."""
        self._diff_results_tree = None

    def drop_label(self) -> None:
        """Forget the summary label so the handlers see it as not yet created."""
        self._diff_summary_label = None

    def compare(self) -> None:
        """Invoke the slot the Compare button triggers."""
        self._on_compare()

    def read_document(self) -> bytes | None:
        """Read the document the way the comparison snapshots it.

        Returns:
            bytes | None: The document bytes, or ``None`` when there is no document.
        """
        return self._read_document_for_diff()

    def cleanup(self) -> None:
        """Run the snapshot cleanup helper."""
        self._cleanup_diff_temp()

    def finished(self, result: dict[str, Any]) -> None:
        """Deliver a typed diff result to the completion handler.

        Args:
            result: Result dictionary shaped like ``execute_diff`` output.
        """
        self._on_diff_finished(result)

    def finished_obj(self, result: object) -> None:
        """Deliver an untyped worker result to the completion forwarder.

        Args:
            result: Raw object a worker emitted.
        """
        self._on_diff_finished_obj(result)

    def error(self, message: str) -> None:
        """Deliver an error string to the error handler.

        Args:
            message: Error text to display.
        """
        self._on_diff_error(message)

    def error_obj(self, exc: object) -> None:
        """Deliver a raw exception object to the error forwarder.

        Args:
            exc: Exception object a worker emitted.
        """
        self._on_diff_error_obj(exc)

    def double_click(self, item: QTreeWidgetItem) -> None:
        """Activate a row the way the tree's double-click signal does.

        Args:
            item: The row to activate.
        """
        self._on_diff_item_double_clicked(item, 0)


def _file_picker(path: str) -> Callable[..., tuple[str, str]]:
    """Build a file-dialog replacement that picks a fixed path.

    Args:
        path: Path the picker reports as chosen.

    Returns:
        Callable[..., tuple[str, str]]: Function with the static dialog's result shape.
    """

    def _pick(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Report the fixed path as the user's choice.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, str]: The path and an empty filter.
        """
        return (path, "")

    return _pick


def _changed_positions(data_a: bytes, data_b: bytes) -> list[int]:
    """List the offsets at which two equally long buffers differ.

    Args:
        data_a: First buffer.
        data_b: Second buffer, the same length as the first.

    Returns:
        list[int]: Every offset whose bytes are not equal.
    """
    return [index for index, (left, right) in enumerate(zip(data_a, data_b, strict=True)) if left != right]


def _expected_summary(data_a: bytes, data_b: bytes) -> str:
    """Build the caption for two buffers that differ in exactly one contiguous run.

    Args:
        data_a: First buffer.
        data_b: Second buffer, the same length as the first.

    Returns:
        str: The caption quoting the region count, differing byte count and both sizes.
    """
    changed = _changed_positions(data_a, data_b)
    return f"1 region(s), {len(changed)} byte(s) differ  [{len(data_a)} vs {len(data_b)} bytes]"


def _expected_row(data_a: bytes, data_b: bytes) -> tuple[str, str, str, str]:
    """Build the single tree row for two buffers differing in one in-place run.

    Args:
        data_a: First buffer.
        data_b: Second buffer, the same length as the first.

    Returns:
        tuple[str, str, str, str]: Offset, length, type and details cells of the row.
    """
    changed = _changed_positions(data_a, data_b)
    first = changed[0]
    length = len(changed)
    assert changed == list(range(first, first + length))
    return (f"0x{first:08X}", str(length), "modified", f"Bytes {first:#010x} - {first + length:#010x}")


def _wait_for_result(qtbot: QtBot, host: _ComparisonHost) -> None:
    """Wait until the summary label no longer reports a computation in progress.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        host: Host whose comparison was started.
    """
    qtbot.waitUntil(lambda: host.summary() != _COMPUTING, timeout=_WAIT_MS)


@pytest.fixture(autouse=True)
def snapshot_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect snapshot tempfiles into a directory the test can inspect.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        Path: The directory that receives the snapshot tempfiles.
    """
    target = tmp_path / "snapshots"
    target.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(target))
    return target


@pytest.fixture
def document() -> intellicrack_hexcore.HexDocument:
    """Open a real document over the first sample buffer.

    Returns:
        intellicrack_hexcore.HexDocument: Document holding ``_DATA_A``.
    """
    return intellicrack_hexcore.HexDocument.open_bytes(_DATA_A)


@pytest.fixture
def hex_widget(qtbot: QtBot, document: intellicrack_hexcore.HexDocument) -> HexEditorWidget:
    """Create a real hex editor widget showing the sample document.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
        document: Document to display.

    Returns:
        HexEditorWidget: Widget with the document attached.
    """
    widget = HexEditorWidget()
    qtbot.addWidget(widget)
    widget.set_document(document)
    return widget


@pytest.fixture
def bridge() -> HexEditorBridge:
    """Create a real hex editor bridge with no document open.

    Returns:
        HexEditorBridge: The bridge whose ``compare_files`` the diff runs through.
    """
    return HexEditorBridge()


@pytest.fixture
def host(
    qtbot: QtBot,
    document: intellicrack_hexcore.HexDocument,
    hex_widget: HexEditorWidget,
    bridge: HexEditorBridge,
) -> Generator[_ComparisonHost]:
    """Create a host whose comparison tab is built and whose workers are joined on teardown.

    Args:
        qtbot: pytest-qt fixture that owns the host.
        document: Document the comparison reads.
        hex_widget: Widget that navigation requests are forwarded to.
        bridge: Bridge the diff runs through.

    Yields:
        _ComparisonHost: Host with the tab built and no file on disk behind its document.
    """
    instance = _ComparisonHost(document, bridge, hex_widget)
    qtbot.addWidget(instance)
    instance.build_tab()
    try:
        yield instance
    finally:
        drain_bridge_workers_for(instance)
        drain_bridge_workers()


def test_goto_offset_moves_the_real_hex_widget(host: _ComparisonHost, hex_widget: HexEditorWidget) -> None:
    """Navigation is forwarded to the attached widget, which moves its cursor and announces it.

    Args:
        host: Host whose comparison tab is built.
        hex_widget: Real widget the host forwards to.
    """
    moved: list[int] = []
    _ = hex_widget.cursor_moved.connect(moved.append)
    host.goto_offset(20)
    assert moved == [20]
    assert getattr(hex_widget, "_cursor_offset") == 20


@pytest.mark.parametrize("widget", [None, types.SimpleNamespace(goto_offset=5), object()], ids=["none", "not-callable", "no-hook"])
def test_goto_offset_ignores_widgets_that_cannot_navigate(document: intellicrack_hexcore.HexDocument, widget: object | None) -> None:
    """A missing widget, a non-callable hook and a widget without the hook are all skipped without error.

    Args:
        document: Document the host holds.
        widget: Navigation target that cannot move a cursor.
    """
    instance = _ComparisonHost(document, None, widget)
    instance.goto_offset(4)
    assert instance.navigation_target is widget
    if isinstance(widget, types.SimpleNamespace):
        assert widget.goto_offset == 5


def test_execute_diff_compares_real_files_and_records_both_paths(tmp_path: Path, bridge: HexEditorBridge) -> None:
    """The helper runs the bridge's file comparison and adds both file paths to the engine result.

    Args:
        tmp_path: Per-test temporary directory holding the two files.
        bridge: Real bridge providing ``compare_files``.
    """
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    file_a.write_bytes(_DATA_A)
    file_b.write_bytes(_DATA_B)
    result = execute_diff(bridge, str(file_a), str(file_b))
    changed = _changed_positions(_DATA_A, _DATA_B)
    differing = [region for region in result["regions"] if region["diff_type"] != "match"]
    assert result["path_a"] == str(file_a)
    assert result["path_b"] == str(file_b)
    assert result["size_a"] == len(_DATA_A)
    assert result["size_b"] == len(_DATA_B)
    assert result["files_identical"] is False
    assert result["total_differences"] == len(changed)
    assert len(differing) == 1
    assert differing[0]["offset_a"] == changed[0]
    assert differing[0]["length"] == len(changed)


@pytest.mark.asyncio
async def test_execute_diff_rejects_a_result_that_was_not_produced_synchronously(tmp_path: Path, bridge: HexEditorBridge) -> None:
    """Called from inside a running loop the bridge call is only scheduled, so there is no dict to enrich.

    Args:
        tmp_path: Per-test temporary directory holding the two files.
        bridge: Real bridge providing ``compare_files``.
    """
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    file_a.write_bytes(_DATA_A)
    file_b.write_bytes(_DATA_B)
    with pytest.raises(TypeError, match="compare_files returned non-dict result"):
        execute_diff(bridge, str(file_a), str(file_b))
    await asyncio.sleep(0)
    await asyncio.sleep(0)


def test_read_document_for_diff_returns_the_document_bytes(host: _ComparisonHost) -> None:
    """The snapshot read yields the document's bytes as ``bytes``, and ``None`` once there is no document.

    Args:
        host: Host holding a real document over ``_DATA_A``.
    """
    snapshot = host.read_document()
    assert snapshot == _DATA_A
    assert type(snapshot) is bytes
    host.document = None
    assert host.read_document() is None


def test_compare_does_nothing_without_a_document(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    snapshot_dir: Path,
    host: _ComparisonHost,
) -> None:
    """With no document the Compare slot returns before it asks for a file or starts a worker.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory holding the files.
        snapshot_dir: Directory that would receive a snapshot.
        host: Host whose comparison tab is built.
    """
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    file_a.write_bytes(_DATA_A)
    file_b.write_bytes(_DATA_B)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(file_b)))
    host.document = None
    host.file_path = file_a
    host.compare()
    assert host.worker is None
    assert not host.summary()
    assert list(snapshot_dir.iterdir()) == []


def test_compare_does_nothing_without_a_bridge(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    snapshot_dir: Path,
    host: _ComparisonHost,
) -> None:
    """With no bridge the Compare slot reports it as unavailable and starts nothing.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory holding the files.
        snapshot_dir: Directory that would receive a snapshot.
        host: Host whose comparison tab is built.
    """
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    file_a.write_bytes(_DATA_A)
    file_b.write_bytes(_DATA_B)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(file_b)))
    host.use_bridge(None)
    host.file_path = file_a
    host.compare()
    assert host.worker is None
    assert not host.summary()
    assert list(snapshot_dir.iterdir()) == []


def test_compare_cancelled_dialog_starts_nothing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    snapshot_dir: Path,
    host: _ComparisonHost,
) -> None:
    """Dismissing the file dialog leaves the tab untouched and writes no snapshot.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory holding the document's file.
        snapshot_dir: Directory that would receive a snapshot.
        host: Host whose comparison tab is built.
    """
    file_a = tmp_path / "a.bin"
    file_a.write_bytes(_DATA_A)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(""))
    host.file_path = file_a
    host.button(_COMPARE_CAPTION).click()
    assert host.worker is None
    assert not host.summary()
    assert host.temp_path is None
    assert list(snapshot_dir.iterdir()) == []


def test_compare_is_ignored_while_a_diff_is_still_running(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    snapshot_dir: Path,
    host: _ComparisonHost,
) -> None:
    """Pressing Compare while a worker is in flight neither replaces it nor writes a snapshot.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory holding the file to compare with.
        snapshot_dir: Directory that would receive a snapshot.
        host: Host whose comparison tab is built.
    """
    file_b = tmp_path / "b.bin"
    file_b.write_bytes(_DATA_B)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(file_b)))
    release = threading.Event()
    blocker = run_callable_async(release.wait, 30.0)
    try:
        host.adopt_worker(blocker)
        host.compare()
        assert host.worker is blocker
        assert not host.summary()
        assert host.temp_path is None
        assert list(snapshot_dir.iterdir()) == []
    finally:
        release.set()
        drain_bridge_workers()


def test_compare_uses_the_file_on_disk_instead_of_a_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
    tmp_path: Path,
    snapshot_dir: Path,
    host: _ComparisonHost,
) -> None:
    """A panel backed by an existing file diffs that file, not the in-memory document.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        qtbot: pytest-qt fixture used to wait for the worker.
        tmp_path: Per-test temporary directory holding the two files.
        snapshot_dir: Directory that would receive a snapshot.
        host: Host whose document holds ``_DATA_A`` while its file holds different bytes.
    """
    on_disk = _HEAD + b"\x5a" * 8 + _TAIL
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    file_a.write_bytes(on_disk)
    file_b.write_bytes(_DATA_B)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(file_b)))
    host.file_path = file_a
    host.compare()
    assert host.summary() == _COMPUTING
    assert host.temp_path is None
    assert list(snapshot_dir.iterdir()) == []
    _wait_for_result(qtbot, host)
    assert host.summary() == _expected_summary(on_disk, _DATA_B)
    assert host.rows() == [_expected_row(on_disk, _DATA_B)]


@pytest.mark.parametrize("path_state", ["no-path", "missing-file"])
def test_compare_snapshots_an_unsaved_document_and_removes_the_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
    tmp_path: Path,
    snapshot_dir: Path,
    host: _ComparisonHost,
    path_state: str,
) -> None:
    """Without a file on disk the document is written to a snapshot, diffed, and the snapshot is deleted afterwards.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        qtbot: pytest-qt fixture used to wait for the worker.
        tmp_path: Per-test temporary directory holding the file to compare with.
        snapshot_dir: Directory that receives the snapshot.
        host: Host whose document holds ``_DATA_A``.
        path_state: Whether the host has no path at all or a path to a file that does not exist.
    """
    file_b = tmp_path / "b.bin"
    file_b.write_bytes(_DATA_B)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(file_b)))
    host.file_path = None if path_state == "no-path" else tmp_path / "gone.bin"
    host.button(_COMPARE_CAPTION).click()
    assert host.summary() == _COMPUTING
    snapshot = host.temp_path
    assert snapshot is not None
    assert snapshot.name.startswith(_SNAPSHOT_PREFIX)
    assert snapshot.parent.resolve() == snapshot_dir.resolve()
    assert snapshot.read_bytes() == _DATA_A
    _wait_for_result(qtbot, host)
    assert host.summary() == _expected_summary(_DATA_A, _DATA_B)
    assert host.rows() == [_expected_row(_DATA_A, _DATA_B)]
    assert not snapshot.exists()
    assert host.temp_path is None
    assert list(snapshot_dir.iterdir()) == []


def test_compare_of_identical_content_reports_identical_files(
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
    tmp_path: Path,
    host: _ComparisonHost,
) -> None:
    """Comparing the document with a file holding the same bytes shows no rows and the identical caption.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        qtbot: pytest-qt fixture used to wait for the worker.
        tmp_path: Per-test temporary directory holding the file to compare with.
        host: Host whose document holds ``_DATA_A``.
    """
    file_b = tmp_path / "same.bin"
    file_b.write_bytes(_DATA_A)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(file_b)))
    host.compare()
    _wait_for_result(qtbot, host)
    assert host.summary() == "Files are identical"
    assert host.rows() == []


def test_compare_with_a_missing_file_reports_the_failure_and_removes_the_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    qtbot: QtBot,
    tmp_path: Path,
    snapshot_dir: Path,
    host: _ComparisonHost,
) -> None:
    """A comparison file that cannot be read produces a failure caption naming it, and the snapshot is still deleted.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        qtbot: pytest-qt fixture used to wait for the worker.
        tmp_path: Per-test temporary directory in which the chosen file does not exist.
        snapshot_dir: Directory that receives the snapshot.
        host: Host whose document holds ``_DATA_A``.
    """
    missing = tmp_path / "does-not-exist.bin"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(missing)))
    host.compare()
    snapshot = host.temp_path
    assert snapshot is not None
    assert snapshot.exists()
    _wait_for_result(qtbot, host)
    assert host.summary().startswith("Diff failed: ")
    assert str(missing) in host.summary()
    assert host.rows() == []
    assert not snapshot.exists()
    assert host.temp_path is None
    assert list(snapshot_dir.iterdir()) == []


def test_compare_with_an_unreadable_document_starts_nothing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    snapshot_dir: Path,
    host: _ComparisonHost,
) -> None:
    """A document that does not offer the read API is reported through the log and nothing is started.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory holding the file to compare with.
        snapshot_dir: Directory that would receive a snapshot.
        host: Host whose comparison tab is built.
    """
    file_b = tmp_path / "b.bin"
    file_b.write_bytes(_DATA_B)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(file_b)))
    host.document = object()
    host.compare()
    assert host.worker is None
    assert not host.summary()
    assert host.temp_path is None
    assert list(snapshot_dir.iterdir()) == []


def test_compare_survives_an_unwritable_snapshot_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    host: _ComparisonHost,
) -> None:
    """When the snapshot cannot be written the failure is logged, no worker starts and nothing is tracked.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog and relocate the temp directory.
        tmp_path: Per-test temporary directory; the redirected temp directory does not exist inside it.
        host: Host whose document holds ``_DATA_A``.
    """
    file_b = tmp_path / "b.bin"
    file_b.write_bytes(_DATA_B)
    absent = tmp_path / "absent-dir"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(file_b)))
    monkeypatch.setattr(tempfile, "tempdir", str(absent))
    host.compare()
    assert host.worker is None
    assert not host.summary()
    assert host.temp_path is None
    assert not absent.exists()


def test_diff_result_forwarders_pass_on_dictionaries_and_exceptions(host: _ComparisonHost) -> None:
    """Dictionary results are rendered and any other object ignored; exceptions become the failure caption.

    Args:
        host: Host whose comparison tab is built.
    """
    host.finished_obj(["not", "a", "dict"])
    assert not host.summary()
    assert host.rows() == []
    host.finished_obj({"files_identical": True})
    assert host.summary() == "Files are identical"
    host.error_obj(ValueError("boom"))
    assert host.summary() == "Diff failed: boom"


def test_cleanup_survives_a_snapshot_path_that_cannot_be_removed(tmp_path: Path, host: _ComparisonHost) -> None:
    """A tracked path the operating system refuses to unlink is forgotten without raising.

    Args:
        tmp_path: Per-test temporary directory holding a directory in place of the snapshot.
        host: Host whose comparison tab is built.
    """
    stubborn = tmp_path / "stubborn"
    stubborn.mkdir()
    host.adopt_temp_path(stubborn)
    host.cleanup()
    assert host.temp_path is None
    assert stubborn.is_dir()


def test_diff_finished_without_a_results_tree_only_cleans_up(tmp_path: Path, host: _ComparisonHost) -> None:
    """A completion that arrives before the tree exists deletes the snapshot and touches nothing else.

    Args:
        tmp_path: Per-test temporary directory holding a stand-in snapshot file.
        host: Host whose comparison tab is built.
    """
    stale = tmp_path / "stale.bin"
    stale.write_bytes(_DATA_A)
    host.adopt_temp_path(stale)
    label = host.label
    host.drop_tree()
    host.finished(intellicrack_hexcore.diff_bytes(_DATA_A, _DATA_B))
    assert not stale.exists()
    assert host.temp_path is None
    assert not label.text()


def test_diff_finished_without_a_summary_label_still_fills_the_tree(host: _ComparisonHost) -> None:
    """The rows are rendered even when the caption label does not exist.

    Args:
        host: Host whose comparison tab is built.
    """
    host.drop_label()
    host.finished(intellicrack_hexcore.diff_bytes(_DATA_A, _DATA_B))
    assert host.rows() == [_expected_row(_DATA_A, _DATA_B)]


def test_diff_error_without_a_summary_label_still_cleans_up(tmp_path: Path, host: _ComparisonHost) -> None:
    """A failure that arrives before the caption label exists still deletes the snapshot.

    Args:
        tmp_path: Per-test temporary directory holding a stand-in snapshot file.
        host: Host whose comparison tab is built.
    """
    stale = tmp_path / "stale.bin"
    stale.write_bytes(_DATA_A)
    host.adopt_temp_path(stale)
    host.drop_label()
    host.error("late failure")
    assert not stale.exists()
    assert host.temp_path is None


def test_double_click_navigates_the_real_widget_to_the_rows_offset(host: _ComparisonHost, hex_widget: HexEditorWidget) -> None:
    """Activating a rendered row moves the hex widget's cursor to the first differing byte.

    Args:
        host: Host whose comparison tab is built.
        hex_widget: Real widget the host forwards to.
    """
    first = _changed_positions(_DATA_A, _DATA_B)[0]
    moved: list[int] = []
    _ = hex_widget.cursor_moved.connect(moved.append)
    host.finished(intellicrack_hexcore.diff_bytes(_DATA_A, _DATA_B))
    host.double_click(host.row_item(0))
    assert moved == [first]
    assert getattr(hex_widget, "_cursor_offset") == first


def test_double_click_on_a_row_without_a_numeric_offset_does_not_navigate(host: _ComparisonHost, hex_widget: HexEditorWidget) -> None:
    """A row carrying no stored offset, or only text, leaves the cursor where it was.

    Args:
        host: Host whose comparison tab is built.
        hex_widget: Real widget the host forwards to.
    """
    host.goto_offset(3)
    moved: list[int] = []
    _ = hex_widget.cursor_moved.connect(moved.append)
    bare = QTreeWidgetItem(["0x00000010", "8", "modified", "Bytes"])
    textual = QTreeWidgetItem(["0x00000010", "8", "modified", "Bytes"])
    textual.setData(0, Qt.ItemDataRole.UserRole, "0x00000010")
    host.double_click(bare)
    host.double_click(textual)
    assert moved == []
    assert getattr(hex_widget, "_cursor_offset") == 3
