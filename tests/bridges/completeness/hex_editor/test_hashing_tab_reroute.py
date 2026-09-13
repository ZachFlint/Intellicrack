# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate for T2-7(b): the hex-editor Hashes tab must route through the bridge.

Prior to this fix ``HashingMixin`` always dispatched background workers that
called the shared ``HexDocument`` directly (``compute_hash``,
``compute_hash_range``, ``verify_pe_checksum``, ``repair_pe_checksum``), and
``CustomCrcDialog`` always used the local streaming CRC fallback, bypassing
``HexEditorBridge``'s ``calculate_hash`` / ``calculate_hash_range`` /
``calculate_hash_custom_crc`` / ``verify_pe_checksum`` / ``repair_pe_checksum``
entirely, even when a bridge was attached.

The fix routes every one of those operations through the corresponding bridge
coroutine via ``run_bridge_coroutine`` whenever a bridge is attached, falling
back to the original document-direct implementation otherwise.

Every test drives the REAL, unmodified hashing mixin against a real
``HexEditorBridge`` and real ``intellicrack_hexcore.HexDocument`` instances;
the only test doubles are a ``HexEditorBridge`` subclass that appends to a
call ledger before delegating to the real implementation via ``super()``, and
a fake dialog class used solely to capture the constructor kwargs
``_on_custom_crc`` passes through (avoiding the real dialog's blocking
``exec()``).
"""

from __future__ import annotations

import shutil
import time
import zlib
from typing import TYPE_CHECKING, Any, ClassVar

import pytest
from PyQt6.QtWidgets import QComboBox, QLabel

import intellicrack.ui.panels.hex_editor.hashing as hashing_module
import intellicrack.ui.panels.hex_editor.widgets as widgets_module
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import priv, priv_method, priv_set


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


intellicrack_hexcore = pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")


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


class _HashingRecordingBridge(HexEditorBridge):
    """``HexEditorBridge`` subclass recording every hashing/PE-checksum accessor call.

    Every override delegates to the real implementation via ``super()`` after
    recording, so the returned values are genuine hexcore computations.
    """

    def __init__(self) -> None:
        """Initialise empty call ledgers alongside the real bridge state."""
        super().__init__()
        self.calculate_hash_calls: list[str] = []
        self.calculate_hash_range_calls: list[tuple[int, int, str]] = []
        self.calculate_hash_custom_crc_calls: list[tuple[int, int, int, int, int]] = []
        self.verify_pe_checksum_calls: int = 0
        self.repair_pe_checksum_calls: int = 0

    async def calculate_hash(self, algorithm: str = "sha256") -> str:
        """Record the call then delegate to the real hash accessor.

        Args:
            algorithm: Hash algorithm forwarded to the real implementation.

        Returns:
            str: The real ``calculate_hash`` result.
        """
        self.calculate_hash_calls.append(algorithm)
        return await super().calculate_hash(algorithm)

    async def calculate_hash_range(self, start: int, end: int, algorithm: str = "sha256") -> str:
        """Record the call then delegate to the real ranged-hash accessor.

        Args:
            start: Start byte offset forwarded to the real implementation.
            end: End byte offset forwarded to the real implementation.
            algorithm: Hash algorithm forwarded to the real implementation.

        Returns:
            str: The real ``calculate_hash_range`` result.
        """
        self.calculate_hash_range_calls.append((start, end, algorithm))
        return await super().calculate_hash_range(start, end, algorithm)

    async def calculate_hash_custom_crc(
        self,
        start: int,
        end: int,
        poly: int,
        init: int,
        width: int,
        *,
        refin: bool = False,
        refout: bool = False,
        xorout: int = 0,
    ) -> str:
        """Record the call then delegate to the real custom-CRC accessor.

        Args:
            start: Start byte offset forwarded to the real implementation.
            end: End byte offset forwarded to the real implementation.
            poly: CRC polynomial forwarded to the real implementation.
            init: Initial CRC register value forwarded to the real implementation.
            width: CRC width in bits forwarded to the real implementation.
            refin: Reflect-input flag forwarded to the real implementation.
            refout: Reflect-output flag forwarded to the real implementation.
            xorout: XOR-out value forwarded to the real implementation.

        Returns:
            str: The real ``calculate_hash_custom_crc`` result.
        """
        self.calculate_hash_custom_crc_calls.append((start, end, poly, init, width))
        return await super().calculate_hash_custom_crc(start, end, poly, init, width, refin=refin, refout=refout, xorout=xorout)

    async def verify_pe_checksum(self) -> dict[str, Any]:
        """Record the call then delegate to the real PE-checksum verifier.

        Returns:
            dict[str, Any]: The real ``verify_pe_checksum`` result.
        """
        self.verify_pe_checksum_calls += 1
        return await super().verify_pe_checksum()

    async def repair_pe_checksum(self) -> dict[str, Any]:
        """Record the call then delegate to the real PE-checksum repair.

        Returns:
            dict[str, Any]: The real ``repair_pe_checksum`` result.
        """
        self.repair_pe_checksum_calls += 1
        return await super().repair_pe_checksum()


class TestHashRoutesThroughBridge:
    """``HashingMixin`` hash actions must route through the attached bridge."""

    @staticmethod
    def test_calculate_hash_routes_through_bridge(qapp: QApplication, tmp_path: Path) -> None:
        """Clicking Calculate must dispatch to ``HexEditorBridge.calculate_hash``.

        Falsifiable: if ``_on_calculate_hash`` were reverted to pass only
        ``(self.document, algo)`` to ``_format_hash_result`` (the pre-fix
        signature), ``bridge.calculate_hash_calls`` would stay empty even
        though a hash result is still displayed (from the document-direct
        fallback instead).

        Args:
            qapp: Session QApplication fixture.
            tmp_path: Pytest-provided temporary directory.
        """
        panel = HexEditorPanel()
        bridge = _HashingRecordingBridge()
        path = tmp_path / "hash_source.bin"
        path.write_bytes(b"The quick brown fox jumps over the lazy dog" * 8)
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(path)) is True

            hash_combo = priv(panel, "_hash_algo_combo", QComboBox)
            hash_combo.setCurrentText("SHA-256")
            priv_method(panel, "_on_calculate_hash")()

            _pump_until(qapp, lambda: bool(bridge.calculate_hash_calls))
            assert bridge.calculate_hash_calls == ["SHA-256"]

            label = priv(panel, "_hash_result_label", QLabel)
            _pump_until(qapp, lambda: "Computing" not in label.text())
            assert "SHA-256:" in label.text()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_hash_selection_routes_through_bridge(qapp: QApplication, tmp_path: Path) -> None:
        """Hashing a selection must dispatch to ``HexEditorBridge.calculate_hash_range``.

        Falsifiable: if ``_on_hash_selection`` were reverted to pass only
        ``(self.document, sel_start, sel_end, algo)`` (the pre-fix signature),
        ``bridge.calculate_hash_range_calls`` would stay empty.

        Args:
            qapp: Session QApplication fixture.
            tmp_path: Pytest-provided temporary directory.
        """
        panel = HexEditorPanel()
        bridge = _HashingRecordingBridge()
        path = tmp_path / "hash_selection_source.bin"
        path.write_bytes(b"0123456789ABCDEF" * 8)
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(path)) is True

            hash_combo = priv(panel, "_hash_algo_combo", QComboBox)
            hash_combo.setCurrentText("SHA-256")
            priv_set(panel, "_selection_start", 4)
            priv_set(panel, "_selection_end", 20)

            priv_method(panel, "_on_hash_selection")()

            _pump_until(qapp, lambda: bool(bridge.calculate_hash_range_calls))
            assert bridge.calculate_hash_range_calls == [(4, 20, "SHA-256")]
        finally:
            panel.deleteLater()


class TestPeChecksumRoutesThroughBridge:
    """PE-checksum verify/repair must route through the attached bridge."""

    @staticmethod
    def test_verify_pe_checksum_routes_through_bridge(qapp: QApplication, real_pe_dll: Path) -> None:
        """Clicking Verify must dispatch to ``HexEditorBridge.verify_pe_checksum``.

        Falsifiable: if ``_on_verify_pe_checksum`` were reverted to pass
        ``self.document.verify_pe_checksum`` directly to the worker,
        ``bridge.verify_pe_checksum_calls`` would stay ``0``.

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real kernel32.dll fixture.
        """
        panel = HexEditorPanel()
        bridge = _HashingRecordingBridge()
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(real_pe_dll)) is True

            priv_method(panel, "_on_verify_pe_checksum")()

            _pump_until(qapp, lambda: bridge.verify_pe_checksum_calls > 0)
            assert bridge.verify_pe_checksum_calls == 1

            status = priv(panel, "_pe_checksum_status", QLabel)
            _pump_until(qapp, lambda: status.text() not in {"Not verified", "Verifying..."})
            assert status.text().startswith(("Valid:", "Invalid:"))
        finally:
            panel.deleteLater()

    @staticmethod
    def test_repair_pe_checksum_routes_through_bridge(qapp: QApplication, real_pe_dll: Path, tmp_path: Path) -> None:
        """Confirming Repair must dispatch to ``HexEditorBridge.repair_pe_checksum``.

        The confirmation ``QMessageBox`` is auto-accepted by this package's
        autouse ``guard_modal_dialogs`` fixture.

        Falsifiable: if ``_repair_pe_checksum_and_notify`` were reverted to
        call ``document.repair_pe_checksum()`` directly,
        ``bridge.repair_pe_checksum_calls`` would stay ``0`` even though the
        file is still repaired (via the document-direct fallback instead).

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real kernel32.dll fixture.
            tmp_path: Pytest-provided temporary directory.
        """
        panel = HexEditorPanel()
        bridge = _HashingRecordingBridge()
        target = tmp_path / "repair_target.dll"
        shutil.copy2(real_pe_dll, target)
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(target)) is True

            priv_method(panel, "_on_repair_pe_checksum")()

            _pump_until(qapp, lambda: bridge.repair_pe_checksum_calls > 0)
            assert bridge.repair_pe_checksum_calls == 1

            status = priv(panel, "_pe_checksum_status", QLabel)
            _pump_until(qapp, lambda: status.text().startswith("Repaired:"))
            assert status.text().startswith("Repaired: 0x")
        finally:
            panel.deleteLater()


class _FakeCustomCrcDialog:
    """Fake ``CustomCrcDialog`` replacement recording its constructor kwargs.

    Stands in for the real dialog only in the wiring test, which must never
    reach the real dialog's blocking ``exec()``.
    """

    calls: ClassVar[list[dict[str, Any]]] = []

    def __init__(self, **kwargs: object) -> None:
        """Record the constructor kwargs the caller passed.

        Args:
            **kwargs: Keyword arguments forwarded by ``_on_custom_crc``.
        """
        type(self).calls.append(kwargs)

    def exec(self) -> int:
        """Return immediately instead of showing a modal dialog.

        Returns:
            int: ``0``, matching ``QDialog.exec``'s ``Rejected`` result code.
        """
        return 0


class TestCustomCrcWiring:
    """``_on_custom_crc`` and the CRC worker must route through the attached bridge."""

    @staticmethod
    def test_on_custom_crc_passes_bridge_to_dialog(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """``_on_custom_crc`` must forward the attached bridge to ``CustomCrcDialog``.

        Falsifiable: if ``_on_custom_crc`` were reverted to omit the
        ``bridge=`` keyword, the recorded call's ``"bridge"`` entry would be
        ``None`` (the dialog's default) instead of the attached bridge
        instance.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Pytest fixture used to replace the real dialog class.
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = _HashingRecordingBridge()
        path = tmp_path / "crc_wiring_source.bin"
        path.write_bytes(b"\x00" * 32)
        _FakeCustomCrcDialog.calls = []
        monkeypatch.setattr(hashing_module, "CustomCrcDialog", _FakeCustomCrcDialog)
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(path)) is True

            priv_method(panel, "_on_custom_crc")()

            assert len(_FakeCustomCrcDialog.calls) == 1
            assert _FakeCustomCrcDialog.calls[0]["bridge"] is bridge
        finally:
            panel.deleteLater()

    @staticmethod
    def test_custom_crc_worker_routes_through_bridge_and_matches_reference(tmp_path: Path) -> None:
        """The CRC worker function must call the bridge and return the correct CRC-32 value.

        Falsifiable: if ``_compute_custom_crc_for_worker`` ignored the
        attached bridge, ``bridge.calculate_hash_custom_crc_calls`` would
        stay empty even though the returned CRC value happens to be correct
        (computed via the local streaming fallback instead).

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        path = tmp_path / "crc_worker_source.bin"
        payload = b"The quick brown fox jumps over the lazy dog" * 4
        path.write_bytes(payload)

        bridge = _HashingRecordingBridge()
        bridge.document = intellicrack_hexcore.HexDocument.open(str(path))
        try:
            worker_fn = priv_method(widgets_module, "_compute_custom_crc_for_worker")
            result = worker_fn(
                bridge,
                None,
                bridge.document,
                len(payload),
                32,
                0x04C11DB7,
                0xFFFFFFFF,
                ref_in=True,
                ref_out=True,
                xor_out=0xFFFFFFFF,
            )

            assert bridge.calculate_hash_custom_crc_calls == [(0, len(payload), 0x04C11DB7, 0xFFFFFFFF, 32)]
            assert result == zlib.crc32(payload)
        finally:
            bridge.document = None
