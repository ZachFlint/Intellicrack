# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for the Cutter panel info-tab refresh defect (D17).

The Headers tab (backed by Rizin's ``ihj``), the Sections table (``iSj``), and
the Imports table (``iij``) all read data the Rizin loader produces when a
binary is opened -- none of the three requires a prior analysis pass. Before
the fix, :class:`~intellicrack.ui.panels.cutter_panel.CutterPanel` only
refreshed these views from ``_on_analysis_complete``, so a binary loaded
without a completed analysis run left the tab empty even though the bridge
could already answer the query correctly.

This test drives a real :class:`CutterPanel` against a real, genuine
rizin/radare2 backend and a real on-disk PE executable. It defeats the panel's
"Analyze" auto-chain by neutralising ``_on_analyze`` on the instance before
loading the binary, so analysis never actually dispatches -- exactly the "Load
Binary (no Analyze)" scenario the defect describes. Pre-fix, with the Headers
refresh reachable only from ``_on_analysis_complete``, the Headers tab stays
permanently empty in this scenario and the test fails red. Post-fix, the panel
refreshes Headers (along with Sections and Imports) directly from the binary
load path, so the tab populates without analysis ever running.

The expected values are never hand-restated: they are read from the same
``CutterBridge.get_headers()`` real bridge call, driven independently against
the same real binary, that the panel's Headers tab itself invokes.
"""

from __future__ import annotations

import os


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import asyncio
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication, QTableWidget, QTabWidget

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.ui.panels.cutter_panel import CutterPanel
from tests._helpers.real_binaries import FixtureUnavailableError, resolve_real_pe_exe


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.core.types import HeaderInfo

pytestmark = [pytest.mark.spawns_process, pytest.mark.usefixtures("qapp")]

_AUDIT_TARGET_PATH: Final[Path] = Path(tempfile.gettempdir()) / "ic_audit_targets" / "ida_9.4.exe"
_LOAD_TIMEOUT_MS: Final[int] = 60_000
_POLL_STEP_MS: Final[int] = 50


def _resolve_target() -> Path:
    """Resolve a real, on-disk PE executable to load through the panel.

    Prefers the committed S19 live-audit target (``ida_9.4.exe``), a
    real-world executable large enough to make an accidental analysis
    dependency in the Headers/Sections/Imports refresh path obvious. Falls
    back to a real System32 executable when the audit target is not present
    on this machine.

    Returns:
        Path: Absolute path to a real, on-disk PE executable.
    """
    if _AUDIT_TARGET_PATH.is_file():
        return _AUDIT_TARGET_PATH
    try:
        return resolve_real_pe_exe()
    except FixtureUnavailableError as exc:
        pytest.skip(str(exc))


async def _backend_available() -> bool:
    """Probe whether a real rizin/radare2 backend is reachable.

    Returns:
        bool: True if :meth:`CutterBridge.is_available` reports the backend.
    """
    return await CutterBridge().is_available()


async def _fetch_reference_headers(target: Path) -> list[HeaderInfo]:
    """Load ``target`` on an independent bridge and return its real headers.

    This bridge instance is entirely separate from the one wired into the
    panel under test: it exists only to obtain ground-truth ``ihj`` values
    from the real backend, against the same real binary, with no analysis
    pass run -- mirroring exactly the load-without-analyze scenario the
    panel itself is driven through below.

    Args:
        target: Real PE executable to load.

    Returns:
        list[HeaderInfo]: The real header fields the backend reports for
        ``target`` immediately after loading, before any analysis.
    """
    bridge = CutterBridge()
    try:
        _ = await bridge.load_binary(target)
        return await bridge.get_headers()
    finally:
        await bridge.shutdown()


def _pump_until(predicate: Callable[[], bool], timeout_ms: int) -> bool:
    """Spin the Qt event loop in short slices until ``predicate`` is true.

    The panel dispatches its real bridge calls onto background
    ``BridgeCallWorker`` threads that deliver results back to the main
    thread via queued Qt signals, so the caller's event loop must be pumped
    for those callbacks to run.

    Args:
        predicate: Zero-argument callable polled after each pumped slice.
        timeout_ms: Total milliseconds to wait before giving up.

    Returns:
        bool: True if ``predicate`` became true within the timeout.
    """
    elapsed = 0
    while elapsed < timeout_ms:
        if predicate():
            return True
        loop = QEventLoop()
        QTimer.singleShot(_POLL_STEP_MS, loop.quit)
        loop.exec()
        app = QApplication.instance()
        if app is not None:
            app.processEvents()
        elapsed += _POLL_STEP_MS
    return predicate()


def _find_ancestor_tab_widget(widget: QTableWidget) -> QTabWidget:
    """Walk a widget's parent chain up to its owning :class:`QTabWidget`.

    Args:
        widget: A widget added as a page of some ``QTabWidget``.

    Returns:
        QTabWidget: The nearest ``QTabWidget`` ancestor. An assertion fails
        if none is found.
    """
    node = widget.parentWidget()
    while node is not None and not isinstance(node, QTabWidget):
        node = node.parentWidget()
    assert node is not None, "Headers tab widget has no QTabWidget ancestor"
    return node


def test_headers_tab_populates_after_load_without_analyze(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Loading a binary must populate Headers even when Analyze never runs.

    Neutralises the panel's own "Analyze" auto-chain so the only trigger
    left for any refresh is the binary-load path, then drives a real
    ``analyze_binary`` (the same call ``_on_load_binary`` makes) against a
    real backend and a real PE file. Selecting the Headers tab afterward
    must show more than zero rows, and every row's Name/Value/Address must
    match the real ``get_headers()`` result obtained independently above.

    Args:
        monkeypatch: Fixture used to replace the panel's ``_on_analyze``
            handler with a no-op recorder so analysis never actually runs.
    """
    target = _resolve_target()

    if not asyncio.run(_backend_available()):
        pytest.skip("rizin/radare2 backend not discoverable on PATH")

    expected = asyncio.run(_fetch_reference_headers(target))
    if not expected:
        pytest.skip(f"{target.name} produced no header fields (ihj) to validate against")

    panel = CutterPanel()
    analyze_calls: list[str] = []

    def _neutered_on_analyze() -> None:
        """Record that the auto-chain fired without running any analysis."""
        analyze_calls.append("called")

    monkeypatch.setattr(panel, "_on_analyze", _neutered_on_analyze)

    bridge = CutterBridge()
    panel.set_bridge(bridge)

    try:
        started = panel.analyze_binary(target)
        assert started, "analyze_binary must report that loading was initiated"

        headers_table = panel._headers_tab._table
        loaded = _pump_until(lambda: bridge.state.binary_loaded, _LOAD_TIMEOUT_MS)
        assert loaded, f"binary load never completed within {_LOAD_TIMEOUT_MS}ms"
        assert analyze_calls, "the load-complete auto-chain never fired _on_analyze"

        populated = _pump_until(lambda: headers_table.rowCount() > 0, _LOAD_TIMEOUT_MS)
        assert populated, (
            "Headers tab is still empty after Load Binary with Analyze neutered: "
            "the refresh is still coupled to _on_analysis_complete instead of the "
            "binary-load path (D17 regression)"
        )

        tabs = _find_ancestor_tab_widget(headers_table)
        tabs.setCurrentIndex(tabs.indexOf(headers_table))

        assert headers_table.rowCount() == len(expected), (
            f"Headers tab shows {headers_table.rowCount()} rows but the real ihj-backed get_headers() call returned {len(expected)} fields"
        )
        for row, field in enumerate(expected):
            name_item = headers_table.item(row, 0)
            value_item = headers_table.item(row, 1)
            address_item = headers_table.item(row, 2)
            assert name_item is not None
            assert value_item is not None
            assert address_item is not None
            assert name_item.text() == field.name
            assert value_item.text() == str(field.value)
            assert address_item.text() == f"0x{field.address:X}"
    finally:
        panel.deleteLater()
        asyncio.run(bridge.shutdown())
