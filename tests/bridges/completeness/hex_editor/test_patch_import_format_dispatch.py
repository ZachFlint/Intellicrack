# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate for T2-7(c): BPS/UPS patch import must use the native-backend-aware bridge method.

Prior to this fix ``PatchesMixin._on_import_patches`` always called the
generic ``HexEditorBridge.import_patches``, which for BPS/UPS payloads never
delegates to ``import_patches_bps`` / ``import_patches_ups`` -- the methods
that prefer the backend's native ``document.import_patches_bps`` /
``import_patches_ups`` accessor -- and instead always falls through the
slow, pure-Python ``_apply_bps_patch`` / ``_apply_ups_patch`` path.

The fix makes ``_on_import_patches`` select ``import_patches_bps`` /
``import_patches_ups`` by the chosen file's ``.bps`` / ``.ups`` extension,
while any other extension (``.ips``, ``.ips32``, or unrecognised) still goes
through the generic ``import_patches`` dispatcher, which already picks the
right handler by magic bytes.

Every test drives the REAL, unmodified ``HexEditorPanel`` and
``HexEditorBridge`` against real ``intellicrack_hexcore.HexDocument``
instances and genuine patch payloads (BPS/UPS blobs produced by the bridge's
own real ``export_patches_bps`` / ``export_patches_ups``, and a hand-built
minimal valid IPS record); the only test double is a ``HexEditorBridge``
subclass that appends to a call ledger before delegating to the real
implementation via ``super()``.
"""

from __future__ import annotations

import asyncio
import base64
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QFileDialog, QMessageBox, QWidget

import intellicrack.ui.panels.hex_editor.patches as patches_module
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import priv_method


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


intellicrack_hexcore = pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async coroutine to completion synchronously.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    return asyncio.run(coro)


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float = 15.0) -> None:
    """Pump the Qt event loop until ``predicate()`` is truthy or the timeout elapses.

    Args:
        qapp: The Qt application instance whose event loop to drive.
        predicate: Zero-argument callable returning a truthy value when done.
        timeout_s: Maximum number of seconds to wait.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        qapp.processEvents()
        time.sleep(0.02)


def _build_bps_patch(original_path: Path, modified_path: Path) -> bytes:
    """Produce a real BPS patch from ``original_path`` to ``modified_path`` via the real bridge.

    Args:
        original_path: Path to the unmodified source file.
        modified_path: Path to the modified target file.

    Returns:
        bytes: Raw BPS patch bytes.
    """
    export_bridge = HexEditorBridge()
    export_bridge.document = intellicrack_hexcore.HexDocument.open(str(modified_path))
    try:
        patch_b64 = _run(export_bridge.export_patches_bps(str(original_path)))
    finally:
        export_bridge.document = None
    return base64.b64decode(patch_b64)


def _build_ups_patch(original_path: Path, modified_path: Path) -> bytes:
    """Produce a real UPS patch from ``original_path`` to ``modified_path`` via the real bridge.

    Args:
        original_path: Path to the unmodified source file.
        modified_path: Path to the modified target file.

    Returns:
        bytes: Raw UPS patch bytes.
    """
    export_bridge = HexEditorBridge()
    export_bridge.document = intellicrack_hexcore.HexDocument.open(str(modified_path))
    try:
        patch_b64 = _run(export_bridge.export_patches_ups(str(original_path)))
    finally:
        export_bridge.document = None
    return base64.b64decode(patch_b64)


def _build_minimal_ips_patch(offset: int, data: bytes) -> bytes:
    """Build a minimal, valid single-record IPS patch.

    Args:
        offset: Byte offset the record writes to.
        data: Replacement bytes for the record.

    Returns:
        bytes: Raw IPS patch bytes (``"PATCH"`` header, one record, ``"EOF"`` trailer).
    """
    return b"PATCH" + offset.to_bytes(3, "big") + len(data).to_bytes(2, "big") + data + b"EOF"


class _PatchesRecordingBridge(HexEditorBridge):
    """``HexEditorBridge`` subclass recording every patch-import dispatch target.

    Every override delegates to the real implementation via ``super()`` after
    recording, so the resulting document bytes reflect a genuine patch
    application rather than a canned response.
    """

    def __init__(self) -> None:
        """Initialise empty call ledgers alongside the real bridge state."""
        super().__init__()
        self.import_patches_calls: list[tuple[str, str | None]] = []
        self.import_patches_bps_calls: list[tuple[str, str]] = []
        self.import_patches_ups_calls: list[tuple[str, str]] = []

    async def import_patches(self, data_b64: str, original_path: str | None = None) -> int:
        """Record the call then delegate to the real generic dispatcher.

        Args:
            data_b64: Base64-encoded patch data forwarded to the real implementation.
            original_path: Optional source path forwarded to the real implementation.

        Returns:
            int: The real ``import_patches`` result.
        """
        self.import_patches_calls.append((data_b64, original_path))
        return await super().import_patches(data_b64, original_path)

    async def import_patches_bps(self, patch_b64: str, original_path: str) -> dict[str, int]:
        """Record the call then delegate to the real BPS importer.

        Args:
            patch_b64: Base64-encoded BPS patch data forwarded to the real implementation.
            original_path: Source path forwarded to the real implementation.

        Returns:
            dict[str, int]: The real ``import_patches_bps`` result.
        """
        self.import_patches_bps_calls.append((patch_b64, original_path))
        return await super().import_patches_bps(patch_b64, original_path)

    async def import_patches_ups(self, patch_b64: str, original_path: str) -> dict[str, int]:
        """Record the call then delegate to the real UPS importer.

        Args:
            patch_b64: Base64-encoded UPS patch data forwarded to the real implementation.
            original_path: Source path forwarded to the real implementation.

        Returns:
            dict[str, int]: The real ``import_patches_ups`` result.
        """
        self.import_patches_ups_calls.append((patch_b64, original_path))
        return await super().import_patches_ups(patch_b64, original_path)


class _InfoWarningRecorder:
    """Records ``show_info`` / ``show_warning`` invocations for assertion."""

    def __init__(self) -> None:
        """Initialise empty message ledgers."""
        self.info_messages: list[str] = []
        self.warning_messages: list[str] = []

    def info(self, parent: QWidget | None, title: str, message: str) -> QMessageBox.StandardButton:
        """Record an informational dialog invocation without displaying it.

        Args:
            parent: Ignored parent widget.
            title: Ignored dialog title.
            message: Message body recorded for assertion.

        Returns:
            QMessageBox.StandardButton: ``Ok``, matching a dismissed info dialog.
        """
        del parent, title
        self.info_messages.append(message)
        return QMessageBox.StandardButton.Ok

    def warning(
        self,
        parent: QWidget | None,
        title: str,
        message: str,
        *,
        exc: BaseException | None = None,
    ) -> QMessageBox.StandardButton:
        """Record a warning dialog invocation without displaying it.

        Args:
            parent: Ignored parent widget.
            title: Ignored dialog title.
            message: Message body recorded for assertion.
            exc: Ignored triggering exception.

        Returns:
            QMessageBox.StandardButton: ``Ok``, matching a dismissed warning dialog.
        """
        del parent, title, exc
        self.warning_messages.append(message)
        return QMessageBox.StandardButton.Ok


def _patch_file_dialog(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    """Stub ``QFileDialog.getOpenFileName`` to return ``path`` without showing a picker.

    Args:
        monkeypatch: Pytest fixture used to install the stub.
        path: Path the stubbed dialog reports as chosen.
    """
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *_a, **_k: (str(path), "")))


class TestBpsUpsImportUsesNativeAwareBridgeMethod:
    """``.bps`` / ``.ups`` imports must dispatch to their dedicated bridge methods."""

    @staticmethod
    def test_bps_import_dispatches_to_import_patches_bps(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A ``.bps`` file must route to ``import_patches_bps``, never the generic dispatcher.

        Falsifiable: if ``_on_import_patches`` were reverted to always call
        ``bridge.import_patches(patch_b64, original_path)`` regardless of
        suffix (the pre-fix behaviour), ``bridge.import_patches_bps_calls``
        would stay empty and ``import_patches_calls`` would carry the entry
        instead.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Pytest fixture used to stub the Import Patches dialog.
            tmp_path: Pytest-provided temporary directory.
        """
        original = tmp_path / "bps_original.bin"
        original.write_bytes(b"A" * 128)
        modified_bytes = bytearray(b"A" * 128)
        modified_bytes[10:14] = b"ZZZZ"
        modified = tmp_path / "bps_modified.bin"
        modified.write_bytes(bytes(modified_bytes))

        patch_path = tmp_path / "delta.bps"
        patch_path.write_bytes(_build_bps_patch(original, modified))
        _patch_file_dialog(monkeypatch, patch_path)

        panel = HexEditorPanel()
        bridge = _PatchesRecordingBridge()
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(original)) is True

            priv_method(panel, "_on_import_patches")()
            _pump_until(
                qapp,
                lambda: bool(bridge.import_patches_bps_calls)
                and bridge.document is not None
                and bytes(bridge.document.read(0, 128)) == bytes(modified_bytes),
            )

            assert len(bridge.import_patches_bps_calls) == 1
            assert bridge.import_patches_bps_calls[0][1] == str(original)
            assert not bridge.import_patches_calls
            assert not bridge.import_patches_ups_calls

            assert bridge.document is not None
            assert bytes(bridge.document.read(0, 128)) == bytes(modified_bytes)
        finally:
            panel.deleteLater()

    @staticmethod
    def test_ups_import_dispatches_to_import_patches_ups(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A ``.ups`` file must route to ``import_patches_ups``, never the generic dispatcher.

        Falsifiable: if ``_on_import_patches`` were reverted to always call
        ``bridge.import_patches(patch_b64, original_path)`` regardless of
        suffix, ``bridge.import_patches_ups_calls`` would stay empty and
        ``import_patches_calls`` would carry the entry instead.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Pytest fixture used to stub the Import Patches dialog.
            tmp_path: Pytest-provided temporary directory.
        """
        original = tmp_path / "ups_original.bin"
        original.write_bytes(b"B" * 96)
        modified_bytes = bytearray(b"B" * 96)
        modified_bytes[40:44] = b"WXYZ"
        modified = tmp_path / "ups_modified.bin"
        modified.write_bytes(bytes(modified_bytes))

        patch_path = tmp_path / "delta.ups"
        patch_path.write_bytes(_build_ups_patch(original, modified))
        _patch_file_dialog(monkeypatch, patch_path)

        panel = HexEditorPanel()
        bridge = _PatchesRecordingBridge()
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(original)) is True

            priv_method(panel, "_on_import_patches")()
            _pump_until(
                qapp,
                lambda: bool(bridge.import_patches_ups_calls)
                and bridge.document is not None
                and bytes(bridge.document.read(0, 96)) == bytes(modified_bytes),
            )

            assert len(bridge.import_patches_ups_calls) == 1
            assert bridge.import_patches_ups_calls[0][1] == str(original)
            assert not bridge.import_patches_calls
            assert not bridge.import_patches_bps_calls

            assert bridge.document is not None
            assert bytes(bridge.document.read(0, 96)) == bytes(modified_bytes)
        finally:
            panel.deleteLater()

    @staticmethod
    def test_bps_import_success_dialog_reports_dict_result_without_warning(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """The success handler must accept the ``{"target_size": int}`` shape without a warning.

        ``import_patches_bps`` returns a dict, unlike the generic
        ``import_patches``'s plain ``int`` count. ``_on_import_patches_success``
        must recognise this shape and report it as one applied patch record
        instead of treating it as an unexpected payload type.

        Falsifiable: if ``_on_import_patches_success`` only accepted
        ``isinstance(result, int)`` (the pre-fix behaviour), it would call
        ``show_warning`` with "Bridge returned an unexpected payload type."
        instead of ``show_info``.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Pytest fixture used to stub the dialog and spy on the info/warning helpers.
            tmp_path: Pytest-provided temporary directory.
        """
        original = tmp_path / "bps_dict_original.bin"
        original.write_bytes(b"C" * 64)
        modified_bytes = bytearray(b"C" * 64)
        modified_bytes[0:4] = b"NEW!"
        modified = tmp_path / "bps_dict_modified.bin"
        modified.write_bytes(bytes(modified_bytes))

        patch_path = tmp_path / "dict_result.bps"
        patch_path.write_bytes(_build_bps_patch(original, modified))
        _patch_file_dialog(monkeypatch, patch_path)

        recorder = _InfoWarningRecorder()
        monkeypatch.setattr(patches_module, "show_info", recorder.info)
        monkeypatch.setattr(patches_module, "show_warning", recorder.warning)

        panel = HexEditorPanel()
        bridge = _PatchesRecordingBridge()
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(original)) is True

            priv_method(panel, "_on_import_patches")()
            _pump_until(qapp, lambda: bool(recorder.info_messages) or bool(recorder.warning_messages))

            assert not recorder.warning_messages
            assert len(recorder.info_messages) == 1
            assert "Applied 1 patch record(s)." in recorder.info_messages[0]
        finally:
            panel.deleteLater()


class TestOtherFormatsStillUseGenericImportPatches:
    """Non-BPS/UPS patch files must keep using the generic dispatcher."""

    @staticmethod
    def test_ips_import_still_uses_generic_import_patches(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A ``.ips`` file must route to the generic ``import_patches``, not the BPS/UPS methods.

        Falsifiable: if ``_on_import_patches`` were changed to route every
        format through ``import_patches_bps``/``import_patches_ups``,
        ``bridge.import_patches_calls`` would stay empty for this ``.ips``
        payload.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Pytest fixture used to stub the Import Patches dialog.
            tmp_path: Pytest-provided temporary directory.
        """
        target = tmp_path / "ips_target.bin"
        target.write_bytes(b"\x00" * 32)

        patch_bytes = _build_minimal_ips_patch(4, b"\x90\x90")
        patch_path = tmp_path / "delta.ips"
        patch_path.write_bytes(patch_bytes)
        _patch_file_dialog(monkeypatch, patch_path)

        panel = HexEditorPanel()
        bridge = _PatchesRecordingBridge()
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(target)) is True

            priv_method(panel, "_on_import_patches")()
            _pump_until(qapp, lambda: bool(bridge.import_patches_calls))

            expected_b64 = base64.b64encode(patch_bytes).decode("ascii")
            assert bridge.import_patches_calls == [(expected_b64, None)]
            assert not bridge.import_patches_bps_calls
            assert not bridge.import_patches_ups_calls

            assert bridge.document is not None
            assert bytes(bridge.document.read(4, 2)) == b"\x90\x90"
        finally:
            panel.deleteLater()
