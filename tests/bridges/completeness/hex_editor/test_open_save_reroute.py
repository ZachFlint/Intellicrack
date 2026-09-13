# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate for T2-7(a): hex-editor OPEN / SAVE / SAVE-AS must route through the bridge.

Prior to this fix ``HexEditorPanel._load_file_impl`` opened
``intellicrack_hexcore.HexDocument`` directly and mirrored the result into the
bridge via the synchronous, non-notifying ``HexEditorBridge.adopt_document``,
which never released whatever document the bridge was already holding.
``HexEditorPanel._on_save`` / ``_perform_save_as`` likewise called
``document.save()`` directly, bypassing ``HexEditorBridge.save`` /
``save_as`` entirely, so the bridge's own ``target_path`` bookkeeping never
tracked a GUI-driven save.

The fix routes all three actions through the corresponding bridge coroutine
via ``run_bridge_coroutine`` when a bridge is attached: opening goes through
``HexEditorBridge.open_file`` (which releases any previously-open document
before opening the new one), and saving goes through ``HexEditorBridge.save``
/ ``save_as``. Because ``open_file`` always publishes ``DOCUMENT_OPENED``
through the shared state holder, and the panel's own callback is not
source-filtered against the bridge's ``"bridge"`` tag, ``HexEditorPanel``
guards against replaying its own open a second time when the notification
echoes back (``_document_already_matches_bridge``).

Every test drives the REAL, unmodified ``HexEditorPanel`` against a real
``HexEditorBridge`` and real ``intellicrack_hexcore.HexDocument`` instances
backed by real temporary files on disk; the only test double is a
``HexEditorBridge`` subclass that appends to a call ledger before delegating
to the real implementation via ``super()``.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QFileDialog

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import HexDocumentState
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")


def _drain_events(qapp: QApplication, iterations: int = 30, delay_s: float = 0.02) -> None:
    """Pump the Qt event loop a bounded number of times.

    Used to give any queued cross-thread ``HexDocumentState`` notification a
    real opportunity to be delivered before asserting it did (or did not)
    trigger further behaviour.

    Args:
        qapp: The Qt application instance whose event loop to drive.
        iterations: Number of ``processEvents`` calls to perform.
        delay_s: Delay, in seconds, between successive calls.
    """
    for _ in range(iterations):
        qapp.processEvents()
        time.sleep(delay_s)


class _OpenSaveRecordingBridge(HexEditorBridge):
    """``HexEditorBridge`` subclass recording ``open_file``/``close_file``/``save``/``save_as`` calls.

    Every override delegates to the real implementation via ``super()`` after
    recording, so the resulting document state reflects genuine hexcore
    behaviour rather than a canned response.
    """

    def __init__(self) -> None:
        """Initialise empty call ledgers alongside the real bridge state."""
        super().__init__()
        self.open_file_calls: list[str] = []
        self.close_file_calls: int = 0
        self.save_calls: list[str | None] = []
        self.save_as_calls: list[str] = []

    async def open_file(self, path: str) -> dict[str, Any]:
        """Record the call then delegate to the real open logic.

        Args:
            path: Filesystem path forwarded to the real implementation.

        Returns:
            dict[str, Any]: The real ``open_file`` result.
        """
        self.open_file_calls.append(path)
        return await super().open_file(path)

    async def close_file(self) -> bool:
        """Record the call then delegate to the real close logic.

        Returns:
            bool: The real ``close_file`` result.
        """
        self.close_file_calls += 1
        return await super().close_file()

    async def save(self, path: str | None = None) -> bool:
        """Record the call then delegate to the real save logic.

        Args:
            path: Save path forwarded to the real implementation.

        Returns:
            bool: The real ``save`` result.
        """
        self.save_calls.append(path)
        return await super().save(path)

    async def save_as(self, path: str) -> bool:
        """Record the call then delegate to the real save-as logic.

        Args:
            path: New file path forwarded to the real implementation.

        Returns:
            bool: The real ``save_as`` result.
        """
        self.save_as_calls.append(path)
        return await super().save_as(path)


class TestOpenRoutesThroughBridge:
    """``HexEditorPanel.load_file`` must open files through the attached bridge."""

    @staticmethod
    def test_second_load_releases_previous_bridge_document(qapp: QApplication, tmp_path: Path) -> None:
        """A second ``load_file`` must close the bridge's previous document before opening the new one.

        Falsifiable: if ``_load_file_impl`` were reverted to call
        ``hexcore.HexDocument.open()`` directly (the pre-fix behaviour),
        ``bridge.open_file_calls`` would stay empty and ``close_file_calls``
        would stay ``0`` even though two different files were loaded through
        the panel.

        Args:
            qapp: Session QApplication fixture.
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = _OpenSaveRecordingBridge()
        path_a = tmp_path / "file_a.bin"
        path_a.write_bytes(b"AAAA" * 16)
        path_b = tmp_path / "file_b.bin"
        path_b.write_bytes(b"BBBB" * 16)
        try:
            panel.set_bridge(bridge)

            assert panel.load_file(str(path_a)) is True
            assert bridge.open_file_calls == [str(path_a)]
            assert bridge.close_file_calls == 0

            assert panel.load_file(str(path_b)) is True
            assert bridge.open_file_calls == [str(path_a), str(path_b)]
            assert bridge.close_file_calls == 1

            assert bridge.document is not None
            assert bridge.document is panel.document
            assert panel.document is not None
            assert bytes(panel.document.read(0, 4)) == b"BBBB"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_panel_initiated_open_does_not_replay_via_state_echo(qapp: QApplication, tmp_path: Path) -> None:
        """A panel-initiated open must not be replayed a second time by its own state echo.

        ``open_file`` always publishes ``DOCUMENT_OPENED`` through the shared
        state holder tagged ``source="bridge"``, which is not filtered
        against the panel's own ``source_id="panel"`` registration. Without
        ``HexEditorPanel._document_already_matches_bridge`` guarding
        ``_on_state_event``, that echo would call ``self.load_file`` a second
        time, appending a second entry to ``open_file_calls``.

        Falsifiable: reverting the guard in ``_on_state_event`` (so
        ``DOCUMENT_OPENED`` unconditionally calls ``self.load_file`` again)
        makes ``bridge.open_file_calls`` grow beyond a single entry for one
        user-driven open.

        Args:
            qapp: Session QApplication fixture.
            tmp_path: Pytest-provided temporary directory.
        """
        panel = HexEditorPanel()
        bridge = _OpenSaveRecordingBridge()
        state = HexDocumentState()
        path = tmp_path / "loop_check.bin"
        path.write_bytes(b"\x01" * 32)
        try:
            panel.set_bridge(bridge)
            bridge.set_state_holder(state)
            panel.set_state_holder(state)

            assert panel.load_file(str(path)) is True
            _drain_events(qapp)

            assert bridge.open_file_calls == [str(path)]
        finally:
            panel.deleteLater()


class TestSaveRoutesThroughBridge:
    """``HexEditorPanel`` save actions must route through the attached bridge."""

    @staticmethod
    def test_save_routes_through_bridge_save(qapp: QApplication, tmp_path: Path) -> None:
        """``panel.save()`` must dispatch to ``HexEditorBridge.save`` and persist the real write.

        Falsifiable: if ``_on_save`` were reverted to call
        ``document.save()`` directly, ``bridge.save_calls`` would stay empty.

        Args:
            qapp: Session QApplication fixture.
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = _OpenSaveRecordingBridge()
        target = tmp_path / "save_target.bin"
        target.write_bytes(b"\x00" * 64)
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(target)) is True
            assert panel.document is not None

            panel.document.write_bytes(0, b"\x90")
            assert panel.save() is True

            assert bridge.save_calls == [str(target)]
            assert target.read_bytes()[:1] == b"\x90"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_save_as_routes_through_bridge_save_as(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """``panel.save_as()`` must dispatch to ``HexEditorBridge.save_as`` and leave the source untouched.

        Falsifiable: if ``_perform_save_as`` were reverted to call
        ``document.save()`` directly, ``bridge.save_as_calls`` would stay
        empty even though the file was written to the new destination.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Pytest fixture used to stub the Save-As dialog.
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = _OpenSaveRecordingBridge()
        source = tmp_path / "save_as_source.bin"
        source.write_bytes(b"\x00" * 64)
        original_bytes = source.read_bytes()
        dest = tmp_path / "save_as_dest.bin"
        monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *_a, **_k: (str(dest), "All Files (*)")))
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(source)) is True
            assert panel.document is not None

            panel.document.write_bytes(0, b"\x90")
            assert panel.save_as() is True

            assert bridge.save_as_calls == [str(dest)]
            assert dest.is_file()
            assert dest.read_bytes()[:1] == b"\x90"
            assert source.read_bytes() == original_bytes
        finally:
            panel.deleteLater()
