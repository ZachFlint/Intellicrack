# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate for T2-7(b): the hex-editor Statistics tab must route through the bridge.

Prior to this fix ``StatisticsMixin._update_statistics`` and
``_on_show_digram_matrix`` always dispatched a background worker that called
the shared ``HexDocument`` directly (``byte_statistics``, ``entropy_map``,
``byte_distribution_full``, ``byte_type_distribution``,
``content_classification``, ``digram_matrix``), bypassing
``HexEditorBridge``'s packed-buffer accessors
(``get_byte_statistics``/``get_entropy``/``get_entropy_map``/
``get_byte_distribution``/``get_byte_type_distribution``/
``get_content_classification``/``get_digram_matrix``) entirely.

The fix adds ``compute_statistics_via_bridge`` / ``compute_digram_matrix_via_bridge``
and routes ``_update_statistics`` / ``_on_show_digram_matrix`` to them whenever
a bridge is attached, falling back to the original document-direct functions
otherwise.

Every test drives the REAL, unmodified statistics mixin functions against a
real ``HexEditorBridge`` and real ``intellicrack_hexcore.HexDocument``
instances backed by real temporary files; the only test double is a
``HexEditorBridge`` subclass that appends to a call ledger before delegating
to the real implementation via ``super()``.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QLabel

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel
from intellicrack.ui.panels.hex_editor.statistics import (
    compute_digram_matrix,
    compute_digram_matrix_via_bridge,
    compute_statistics,
    compute_statistics_via_bridge,
)
from intellicrack.ui.panels.hex_editor.widgets import DigramMatrixDialog

from .conftest import priv, priv_method


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


intellicrack_hexcore = pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")


class _StatsRecordingBridge(HexEditorBridge):
    """``HexEditorBridge`` subclass recording every statistics accessor call.

    Every override delegates to the real implementation via ``super()`` after
    recording, so the returned numbers are genuine hexcore computations.
    """

    def __init__(self) -> None:
        """Initialise empty call counters alongside the real bridge state."""
        super().__init__()
        self.get_byte_statistics_calls: int = 0
        self.get_entropy_calls: int = 0
        self.get_entropy_map_calls: int = 0
        self.get_byte_distribution_calls: int = 0
        self.get_byte_type_distribution_calls: int = 0
        self.get_content_classification_calls: int = 0
        self.get_digram_matrix_calls: int = 0

    async def get_byte_statistics(self) -> list[dict[str, int]]:
        """Record the call then delegate to the real byte-statistics accessor.

        Returns:
            list[dict[str, int]]: The real ``get_byte_statistics`` result.
        """
        self.get_byte_statistics_calls += 1
        return await super().get_byte_statistics()

    async def get_entropy(self) -> float:
        """Record the call then delegate to the real entropy accessor.

        Returns:
            float: The real ``get_entropy`` result.
        """
        self.get_entropy_calls += 1
        return await super().get_entropy()

    async def get_entropy_map(self, block_size: int = 4096) -> list[float]:
        """Record the call then delegate to the real entropy-map accessor.

        Args:
            block_size: Block size in bytes forwarded to the real implementation.

        Returns:
            list[float]: The real ``get_entropy_map`` result.
        """
        self.get_entropy_map_calls += 1
        return await super().get_entropy_map(block_size)

    async def get_byte_distribution(self) -> list[int]:
        """Record the call then delegate to the real byte-distribution accessor.

        Returns:
            list[int]: The real ``get_byte_distribution`` result.
        """
        self.get_byte_distribution_calls += 1
        return await super().get_byte_distribution()

    async def get_byte_type_distribution(self) -> dict[str, int]:
        """Record the call then delegate to the real byte-type-distribution accessor.

        Returns:
            dict[str, int]: The real ``get_byte_type_distribution`` result.
        """
        self.get_byte_type_distribution_calls += 1
        return await super().get_byte_type_distribution()

    async def get_content_classification(self, block_size: int = 4096) -> list[int]:
        """Record the call then delegate to the real content-classification accessor.

        Args:
            block_size: Block size in bytes forwarded to the real implementation.

        Returns:
            list[int]: The real ``get_content_classification`` result.
        """
        self.get_content_classification_calls += 1
        return await super().get_content_classification(block_size)

    async def get_digram_matrix(self, top_k: int = 0) -> dict[str, Any]:
        """Record the call then delegate to the real digram-matrix accessor.

        Args:
            top_k: Top-K selector forwarded to the real implementation.

        Returns:
            dict[str, Any]: The real ``get_digram_matrix`` result.
        """
        self.get_digram_matrix_calls += 1
        return await super().get_digram_matrix(top_k)


def _no_op_dialog_exec(_self: DigramMatrixDialog) -> int:
    """Return immediately instead of showing the modal digram-matrix dialog.

    Args:
        _self: The dialog instance whose ``exec`` call is being stubbed.

    Returns:
        int: ``0``, matching ``QDialog.exec``'s ``Rejected`` result code.
    """
    return 0


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float = 10.0) -> None:
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


class TestComputeStatisticsViaBridgeMatchesDirectComputation:
    """``compute_statistics_via_bridge`` must agree with the document-direct oracle."""

    @staticmethod
    def test_bridge_statistics_match_document_direct_statistics(tmp_path: Path) -> None:
        """Every field of the bridge-routed result must equal the document-direct result.

        Falsifiable: if ``compute_statistics_via_bridge`` mis-mapped a bridge
        accessor's return shape (e.g. treating ``get_byte_type_distribution``'s
        dict keys in the wrong order, or forgetting to route entropy through
        ``get_entropy``), the corresponding field would diverge from the
        document-direct oracle computed by ``compute_statistics``.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        path = tmp_path / "stats_source.bin"
        payload = bytes(range(256)) * 8 + b"\x00" * 128
        path.write_bytes(payload)

        bridge = _StatsRecordingBridge()
        bridge.document = intellicrack_hexcore.HexDocument.open(str(path))
        try:
            via_bridge = compute_statistics_via_bridge(bridge, 64)
            direct = compute_statistics(bridge.document, 64)

            assert bridge.get_byte_statistics_calls == 1
            assert bridge.get_entropy_calls == 1
            assert bridge.get_entropy_map_calls == 1
            assert bridge.get_byte_distribution_calls == 1
            assert bridge.get_byte_type_distribution_calls == 1
            assert bridge.get_content_classification_calls == 1

            assert sorted(via_bridge.byte_stats) == sorted(direct.byte_stats)
            assert via_bridge.total == direct.total
            assert via_bridge.entropy == pytest.approx(direct.entropy, abs=1e-9)
            assert via_bridge.entropy_values == pytest.approx(direct.entropy_values or [])
            assert via_bridge.dist_counts == direct.dist_counts
            assert via_bridge.type_dist == direct.type_dist
            assert via_bridge.classification == direct.classification
        finally:
            bridge.document = None

    @staticmethod
    def test_bridge_digram_matrix_matches_document_direct_matrix(tmp_path: Path) -> None:
        """The bridge-routed digram matrix must equal the document-direct matrix.

        Falsifiable: if ``compute_digram_matrix_via_bridge`` failed to
        request the full matrix (e.g. leaving ``top_k`` non-zero) or
        mis-extracted the ``"matrix"`` key, the returned list would not
        match the document-direct oracle.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        path = tmp_path / "digram_source.bin"
        path.write_bytes(bytes(range(256)) * 4)

        bridge = _StatsRecordingBridge()
        bridge.document = intellicrack_hexcore.HexDocument.open(str(path))
        try:
            via_bridge = compute_digram_matrix_via_bridge(bridge)
            direct = compute_digram_matrix(bridge.document)

            assert bridge.get_digram_matrix_calls == 1
            assert via_bridge == direct
            assert len(via_bridge) == 65536
        finally:
            bridge.document = None


class TestStatisticsTabWiring:
    """The real panel must select the bridge-routed worker when a bridge is attached."""

    @staticmethod
    def test_update_statistics_routes_through_bridge(qapp: QApplication, tmp_path: Path) -> None:
        """Loading a file with a bridge attached must dispatch every statistics accessor.

        Falsifiable: if ``_update_statistics`` were reverted to always pass
        ``compute_statistics`` to the worker, every ``get_*`` counter on the
        bridge would stay ``0`` even though the entropy label ends up
        populated (from the document-direct fallback instead).

        Args:
            qapp: Session QApplication fixture.
            tmp_path: Pytest-provided temporary directory.
        """
        panel = HexEditorPanel()
        bridge = _StatsRecordingBridge()
        path = tmp_path / "wiring_source.bin"
        path.write_bytes(bytes(range(256)) * 4)
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(path)) is True

            _pump_until(qapp, lambda: bridge.get_content_classification_calls > 0)

            assert bridge.get_byte_statistics_calls >= 1
            assert bridge.get_entropy_calls >= 1
            assert bridge.get_entropy_map_calls >= 1
            assert bridge.get_byte_distribution_calls >= 1
            assert bridge.get_byte_type_distribution_calls >= 1
            assert bridge.get_content_classification_calls >= 1

            entropy_label = priv(panel, "_entropy_label", (QLabel, type(None)))
            assert entropy_label is not None
            _pump_until(qapp, lambda: entropy_label.text() != "Computing...")
            assert entropy_label.text() not in {"Computing...", "—"}
        finally:
            panel.deleteLater()

    @staticmethod
    def test_digram_matrix_routes_through_bridge(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Requesting the digram matrix with a bridge attached must call ``get_digram_matrix``.

        ``DigramMatrixDialog.exec`` is monkeypatched to a no-op so the modal
        dialog opened on success never blocks this headless test.

        Falsifiable: if ``_on_show_digram_matrix`` were reverted to always
        pass ``compute_digram_matrix`` to the worker, ``get_digram_matrix_calls``
        would stay ``0``.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Pytest fixture used to stub the modal matrix dialog.
            tmp_path: Pytest-provided temporary directory.
        """
        monkeypatch.setattr(DigramMatrixDialog, "exec", _no_op_dialog_exec)

        panel = HexEditorPanel()
        bridge = _StatsRecordingBridge()
        path = tmp_path / "digram_wiring_source.bin"
        path.write_bytes(bytes(range(256)) * 4)
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(path)) is True

            priv_method(panel, "_on_show_digram_matrix")()

            _pump_until(qapp, lambda: bridge.get_digram_matrix_calls > 0)
            assert bridge.get_digram_matrix_calls == 1
        finally:
            panel.deleteLater()
