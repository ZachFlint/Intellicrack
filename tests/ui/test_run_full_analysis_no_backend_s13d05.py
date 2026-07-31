# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for S13-D05: "Run Full Analysis" with no disassembler backend.

``MainWindow._on_run_full_analysis`` (in ``src/intellicrack/ui/app.py``)
re-runs the orchestrator's aggregated bridge analysis and, in
``_on_full_analysis_done``, decides how to report the outcome. Before the
fix, that decision was made with a bare ``isinstance(result,
BridgeAnalysisSummary)`` check. ``AnalysisAggregator.aggregate`` (see
``src/intellicrack/core/analysis_aggregator.py``) always returns a real
``BridgeAnalysisSummary`` -- even when neither Ghidra nor Cutter is
connected, in which case it falls back to the pre-loaded ``BinaryInfo``
metadata, appends a "No bridges connected" note, and sets
``complete=False`` -- so the ``isinstance`` check alone was always true and
the handler unconditionally reported "Full analysis complete", silently
presenting a misleading 0-functions result exactly as if the binary
genuinely had no functions.

The fix additionally checks ``result.complete`` (the aggregator's own
signal that at least one bridge actually contributed data) and, when it is
``False``, surfaces an actionable "no backend connected" warning instead of
the "complete" status.

This test drives the real ``_run_bridge_analysis`` -> ``AnalysisAggregator``
pipeline end to end against a real ``BinaryInfo`` (parsed from a genuine
Windows system DLL via the orchestrator's own ``_load_binary``) with an
otherwise-empty ``ToolRegistry`` -- i.e. no Ghidra/Cutter bridge registered,
the real "no backend connected" condition -- through
``MainWindow._on_run_full_analysis`` on a real ``MainWindow``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import QApplication, QMessageBox

from intellicrack.core.session import Session
from intellicrack.core.tools import ToolError
from intellicrack.core.types import BinaryInfo, ProviderName
from intellicrack.ui.app import MainWindow
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine


if TYPE_CHECKING:
    from collections.abc import Generator

    from pytestqt.qtbot import QtBot

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator

_SYSTEM_DLL = Path(r"C:\Windows\System32\kernel32.dll")
_WAIT_TIMEOUT_MS = 15000


@pytest.fixture
def window(qapp: QApplication, real_config: Config, real_orchestrator: Orchestrator) -> Generator[MainWindow]:
    """Construct a real ``MainWindow`` from real config/orchestrator fixtures.

    Args:
        qapp: Session QApplication fixture.
        real_config: Real ``Config`` fixture from ``tests/ui/conftest.py``.
        real_orchestrator: Real ``Orchestrator`` fixture from ``tests/ui/conftest.py``.

    Yields:
        MainWindow: The window under test. Its ``ToolRegistry`` has no
        registered bridges (the real "no disassembler backend" condition).
    """
    del qapp
    win = MainWindow(real_config, real_orchestrator)
    try:
        yield win
    finally:
        win.close()


class TestRunFullAnalysisWithNoBackendConnected:
    """S13-D05: a "0 functions" outcome with no backend must never read as success."""

    def test_no_backend_surfaces_actionable_warning_instead_of_silent_success(
        self,
        window: MainWindow,
        qtbot: QtBot,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With no Ghidra/Cutter bridge registered, the run must warn, not claim completion.

        Args:
            window: Real MainWindow fixture with an empty ``ToolRegistry``.
            qtbot: pytest-qt bot used to pump the event loop for the queued
                async-bridge callback.
            monkeypatch: pytest monkeypatch fixture.
        """
        assert _SYSTEM_DLL.exists(), "test requires a real Windows system DLL fixture"

        tool_registry = window._orchestrator.tool_registry
        with pytest.raises(ToolError):
            tool_registry.get_ghidra_bridge()
        with pytest.raises(ToolError):
            tool_registry.get_cutter_bridge()

        binary_info = run_bridge_coroutine(window._orchestrator._load_binary(_SYSTEM_DLL))
        assert isinstance(binary_info, BinaryInfo)

        session = run_bridge_coroutine(
            window._orchestrator._sessions.create(ProviderName.OLLAMA, "test-model", "no-backend-session"),
        )
        assert isinstance(session, Session)
        session.add_binary(binary_info)
        window._orchestrator._current_session = session
        window.current_binary = binary_info.path

        captured_warnings: list[tuple[object, ...]] = []

        def _capture_warning(*args: object, **kwargs: object) -> QMessageBox.StandardButton:
            """Record a ``QMessageBox.warning`` invocation instead of showing a real dialog.

            Args:
                *args: Positional arguments forwarded by the real call site
                    (``parent``, ``title``, ``text``, ...).
                **kwargs: Keyword arguments forwarded by the real call site.

            Returns:
                QMessageBox.StandardButton: A benign ``Ok`` acknowledgement.
            """
            del kwargs
            captured_warnings.append(args)
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "warning", staticmethod(_capture_warning))

        window._on_run_full_analysis()

        qtbot.waitUntil(lambda: bool(captured_warnings), timeout=_WAIT_TIMEOUT_MS)

        assert len(captured_warnings) == 1, f"expected exactly one actionable warning, got {captured_warnings!r}"
        warning_args = cast("tuple[object, ...]", captured_warnings[0])
        message_text = " ".join(str(a) for a in warning_args).lower()

        assert "ghidra" in message_text or "cutter" in message_text, (
            f"warning must name a disassembler backend to connect (Ghidra/Cutter); got: {message_text!r}"
        )
        assert "connect" in message_text, f"warning must be actionable (tell the user to connect a backend); got: {message_text!r}"

        assert window.status_label.text() != "Full analysis complete", (
            "status bar must not claim completion when no analysis backend actually contributed data"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
