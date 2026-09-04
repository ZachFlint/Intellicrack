# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S19 hex-editor defects D01, D05, D06, D07, D24, D25.

Drives the real ``HexEditorPanel`` (with a real ``intellicrack_hexcore``
document) end to end for each fix:

* D01 -- a uint32 little-endian numeric search for a value known to exist
  at a specific offset must navigate to and highlight that offset.
* D05 -- an invalid hex pattern fed to Replace All must produce a
  friendly message that never contains the substring ``fromhex``.
* D06 -- entering a bare numeral (no ``0x`` prefix) into the "Offset
  (hex)" Go field must be parsed as hex, matching the field's own label.
* D07 -- double-clicking a bookmark row must move the hex cursor to that
  bookmark's offset.
* D24 -- a bookmark added to a file must survive closing and reopening
  that same file (persisted to a JSON sidecar).
* D25 -- switching from one open file to another must reset the
  bookmarks tree so it reflects the newly opened document only.

Each test drives the production ``SearchMixin`` / ``BookmarksMixin`` /
``HexEditorPanel`` handlers directly (no behaviour is reimplemented in the
test) so a regression in the fixed wiring makes the corresponding test
fail.
"""

from __future__ import annotations

import os
import struct
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest


if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QApplication

    from intellicrack.ui.panels.async_bridge import GenericCallableWorker

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor import search as search_module
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real hex documents",
)

pytestmark = pytest.mark.integration


_AUDIT_TARGET_PATH: Final[Path] = Path(tempfile.gettempdir()) / "ic_audit_targets" / "ida_9.4.exe"
_AUDIT_TARGET_VALUE: Final[int] = 1207985577
"""Ground-truth uint32-LE value from the S19 live audit (bytes A9 65 00 48)."""

_FIXTURE_VALUE: Final[int] = 0xDEADBEEF
_FIXTURE_OFFSET: Final[int] = 0x800
_FIXTURE_SIZE: Final[int] = 4096

_WORKER_TIMEOUT_S: Final[float] = 20.0


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float = _WORKER_TIMEOUT_S) -> bool:
    """Pump the Qt event loop until ``predicate()`` is true or the timeout elapses.

    A ``GenericCallableWorker`` runs its callable on a background
    ``QThread`` and delivers ``call_finished`` / ``call_error`` back to the
    GUI thread via a queued Qt connection, which is only dispatched while
    the main-thread event loop is processing events. Polling
    ``isRunning()`` without pumping would leave the queued signal
    undelivered forever.

    Args:
        qapp: The active QApplication whose event loop is pumped.
        predicate: Zero-argument callable polled after each pump.
        timeout_s: Maximum number of seconds to wait.

    Returns:
        bool: ``True`` if ``predicate()`` became true before the timeout.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        qapp.processEvents()
        if predicate():
            qapp.processEvents()
            return True
        time.sleep(0.02)
    return predicate()


def _resolve_numeric_search_target(tmp_path: Path) -> tuple[Path, int, int]:
    """Resolve a file, a uint32-LE value, and its offset for the D01 gate.

    Prefers the real S19 audit target (``ida_9.4.exe``) when present on
    disk, deriving the expected offset directly from the file's own bytes
    (never hardcoding an offset for real data). Falls back to a
    deterministically generated fixture -- never an unconditional skip --
    when the audit target is unavailable.

    Args:
        tmp_path: Per-test temporary directory used for the fallback fixture.

    Returns:
        tuple[Path, int, int]: ``(file_path, value, expected_offset)``.
    """
    if _AUDIT_TARGET_PATH.is_file():
        data = _AUDIT_TARGET_PATH.read_bytes()
        needle = struct.pack("<I", _AUDIT_TARGET_VALUE)
        offset = data.find(needle)
        if offset != -1:
            return _AUDIT_TARGET_PATH, _AUDIT_TARGET_VALUE, offset

    fixture_path = tmp_path / "d01_numeric_fixture.bin"
    payload = bytearray(_FIXTURE_SIZE)
    payload[_FIXTURE_OFFSET : _FIXTURE_OFFSET + 4] = struct.pack("<I", _FIXTURE_VALUE)
    fixture_path.write_bytes(bytes(payload))
    return fixture_path, _FIXTURE_VALUE, _FIXTURE_OFFSET


def _make_panel() -> HexEditorPanel:
    """Construct a real ``HexEditorPanel`` with disassembly follow-cursor disabled.

    Follow-cursor is disabled because it debounces a bridge-backed
    auto-disassemble on every cursor move; with no bridge attached that
    would pop a modal warning dialog that blocks an offscreen test.

    Returns:
        HexEditorPanel: A freshly constructed panel ready for ``load_file``.
    """
    panel = HexEditorPanel()
    if panel._disasm_follow_cursor is not None:
        panel._disasm_follow_cursor.setChecked(False)
    return panel


class TestNumericSearchNavigatesToKnownOffset:
    """D01: a uint32-LE numeric search must find and navigate to a known offset."""

    @staticmethod
    def test_numeric_search_finds_and_navigates(tmp_path: Path, qapp: QApplication) -> None:
        """A uint32-LE search for a value known to exist navigates to its offset.

        Args:
            tmp_path: Pytest temporary directory fixture.
            qapp: QApplication fixture (also pumped while the worker runs).
        """
        path, value, expected_offset = _resolve_numeric_search_target(tmp_path)
        panel = _make_panel()
        try:
            assert panel.load_file(path), "load_file must succeed for the numeric-search target"
            assert panel._numeric_value_input is not None
            assert panel._numeric_size_combo is not None
            assert panel._numeric_type_combo is not None
            assert panel._numeric_endian_combo is not None
            assert panel._hex_widget is not None

            panel._numeric_value_input.setText(str(value))
            panel._numeric_size_combo.setCurrentText("32-bit")
            panel._numeric_type_combo.setCurrentText("Unsigned Int")
            panel._numeric_endian_combo.setCurrentText("Little Endian")

            value_input = panel._numeric_value_input
            panel._on_numeric_search()
            worker: GenericCallableWorker | None = panel._numeric_search_worker
            assert worker is not None, "_on_numeric_search must dispatch a background worker"
            # Dispatch disables the value input; both the success and error
            # completion handlers re-enable it. Poll that flag rather than the
            # worker's own liveness: GenericCallableWorker wires
            # ``finished -> deleteLater``, so once the thread finishes its
            # underlying C++ object is destroyed and ``worker.isRunning()``
            # raises ``RuntimeError`` -- a race that would mask, not measure,
            # the search result. The completion flag survives worker deletion.
            assert not value_input.isEnabled(), "dispatch must disable the value input while the search runs"
            assert _pump_until(qapp, value_input.isEnabled), "numeric search worker never finished"

            assert panel._search_results, "numeric search found no matches for a value known to exist in the file"
            assert panel._search_results[0][0] == expected_offset, (
                f"expected first match at 0x{expected_offset:X}, got 0x{panel._search_results[0][0]:X}"
            )
            assert panel._hex_widget._cursor_offset == expected_offset, (
                "numeric search must navigate the hex cursor to the matched offset"
            )
        finally:
            panel._cleanup()


class TestInvalidHexReplaceMessage:
    """D05: invalid-hex Replace All must never leak the raw ``fromhex`` exception text."""

    @staticmethod
    def test_replace_all_invalid_hex_shows_friendly_message(
        tmp_path: Path,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Replace All with a malformed hex pattern shows a friendly message.

        Args:
            tmp_path: Pytest temporary directory fixture.
            qapp: QApplication fixture.
            monkeypatch: Pytest fixture used to intercept the module-level
                ``show_warning`` import inside ``search.py``.
        """
        _ = qapp
        path = tmp_path / "d05_target.bin"
        path.write_bytes(bytes(range(256)))

        panel = _make_panel()
        try:
            panel.set_bridge(HexEditorBridge())
            assert panel.load_file(path)
            assert panel._search_mode_combo is not None
            assert panel._search_input is not None
            assert panel._replace_input is not None

            panel._search_mode_combo.setCurrentText("Hex")
            panel._search_input.setText("D 5A90de")
            panel._replace_input.setText("5B91")

            captured: dict[str, str] = {}

            def _fake_warn(_parent: object, title: str, message: str) -> None:
                """Capture the warning dialog's title and message instead of showing it.

                Args:
                    _parent: Parent widget argument (unused).
                    title: Dialog title passed by the production handler.
                    message: Dialog message passed by the production handler.
                """
                captured["title"] = title
                captured["message"] = message

            monkeypatch.setattr(search_module, "show_warning", _fake_warn)

            panel._on_replace_all()

            assert captured, "Replace All with invalid hex must show a warning dialog"
            assert "fromhex" not in captured["message"], f"raw fromhex exception text leaked: {captured['message']!r}"
            assert "invalid" in captured["message"].lower(), f"expected a friendly invalid-hex message, got: {captured['message']!r}"
        finally:
            panel._cleanup()


class TestGotoOffsetParsesBareInputAsHex:
    """D06: the "Offset (hex)" Go field must parse bare digits as hex, not decimal."""

    @staticmethod
    def test_bare_numeral_goes_to_hex_offset(tmp_path: Path, qapp: QApplication) -> None:
        """Typing "7000" (no ``0x`` prefix) into Go navigates to offset 0x7000.

        Args:
            tmp_path: Pytest temporary directory fixture.
            qapp: QApplication fixture.
        """
        _ = qapp
        path = tmp_path / "d06_target.bin"
        path.write_bytes(bytes(range(256)) * 128)  # 32768 bytes, comfortably > 0x7000

        panel = _make_panel()
        try:
            assert panel.load_file(path)
            assert panel._offset_input is not None
            assert panel._hex_widget is not None

            panel._offset_input.setText("7000")
            panel._on_goto_offset()

            assert panel._hex_widget._cursor_offset == 0x7000, (
                f"bare '7000' must be parsed as hex (0x7000), cursor is at 0x{panel._hex_widget._cursor_offset:X}"
            )
        finally:
            panel._cleanup()


class TestBookmarkDoubleClickNavigates:
    """D07: double-clicking a bookmark row must move the hex cursor to its offset."""

    @staticmethod
    def test_double_click_moves_cursor_to_bookmark_offset(tmp_path: Path, qapp: QApplication) -> None:
        """Double-clicking a bookmark row navigates the cursor to that bookmark's offset.

        Args:
            tmp_path: Pytest temporary directory fixture.
            qapp: QApplication fixture.
        """
        _ = qapp
        path = tmp_path / "d07_target.bin"
        path.write_bytes(bytes(range(256)) * 16)  # 4096 bytes

        panel = _make_panel()
        try:
            assert panel.load_file(path)
            assert panel.document is not None
            assert panel._bookmarks_tree is not None
            assert panel._hex_widget is not None

            bookmark_offset = 0x100
            panel.document.add_bookmark(bookmark_offset, 4, "TestBookmark", "#FF0000")
            panel._refresh_bookmarks_tree()

            item = panel._bookmarks_tree.topLevelItem(0)
            assert item is not None, "bookmark must appear in the tree after _refresh_bookmarks_tree"

            panel._hex_widget.goto_offset(0)
            assert panel._hex_widget._cursor_offset == 0

            panel._on_bookmark_double_clicked(item, 0)

            assert panel._hex_widget._cursor_offset == bookmark_offset, (
                f"double-clicking the bookmark row must move the cursor to 0x{bookmark_offset:X}, "
                f"got 0x{panel._hex_widget._cursor_offset:X}"
            )
        finally:
            panel._cleanup()


class TestBookmarkPersistsAcrossReload:
    """D24: a bookmark added to a file must survive closing and reopening that file."""

    @staticmethod
    def test_bookmark_survives_close_and_reopen(tmp_path: Path, qapp: QApplication) -> None:
        """A bookmark added and persisted is present after reopening the same file.

        Args:
            tmp_path: Pytest temporary directory fixture.
            qapp: QApplication fixture.
        """
        _ = qapp
        path = tmp_path / "d24_target.bin"
        path.write_bytes(bytes(range(256)) * 16)

        offset = 0x50
        label = "PersistBM"

        panel = _make_panel()
        try:
            assert panel.load_file(path)
            assert panel.document is not None
            panel.document.add_bookmark(offset, 2, label, "#00FF00")
            panel._persist_bookmarks_sidecar()

            sidecar = path.with_name(path.name + ".icbm.json")
            assert sidecar.is_file(), "adding a bookmark must write the .icbm.json sidecar"
        finally:
            panel._cleanup()

        panel2 = _make_panel()
        try:
            assert panel2.load_file(path)
            assert panel2.document is not None
            bookmarks = panel2.document.get_bookmarks()
            assert any(bm.offset == offset and bm.label == label for bm in bookmarks), (
                f"reopening the file must restore the persisted bookmark; got {[(b.offset, b.label) for b in bookmarks]}"
            )
        finally:
            panel2._cleanup()


class TestBookmarksTreeResetsOnFileSwitch:
    """D25: opening a different file must reset the bookmarks tree, not show the prior file's rows."""

    @staticmethod
    def test_tree_reflects_newly_opened_file_only(tmp_path: Path, qapp: QApplication) -> None:
        """Opening file B after file A must not leave file A's bookmark rows visible.

        Args:
            tmp_path: Pytest temporary directory fixture.
            qapp: QApplication fixture.
        """
        _ = qapp
        path_a = tmp_path / "d25_a.bin"
        path_a.write_bytes(bytes(range(256)) * 4)
        path_b = tmp_path / "d25_b.bin"
        path_b.write_bytes(bytes(reversed(range(256))) * 4)

        panel = _make_panel()
        try:
            assert panel.load_file(path_a)
            assert panel.document is not None
            assert panel._bookmarks_tree is not None

            panel.document.add_bookmark(0x10, 1, "OnlyInA", "#0000FF")
            panel._refresh_bookmarks_tree()
            assert panel._bookmarks_tree.topLevelItemCount() == 1

            assert panel.load_file(path_b)
            assert panel._bookmarks_tree.topLevelItemCount() == 0, (
                "opening a different file must reset the bookmarks tree instead of keeping the previous file's rows"
            )
        finally:
            panel._cleanup()
