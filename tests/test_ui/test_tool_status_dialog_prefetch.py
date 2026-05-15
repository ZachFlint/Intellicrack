# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for :class:`ToolStatusDialog` prefetched-status reuse.

Covers F-0007 (ui-app-core tool_status pre-fetch reuse): when a caller
supplies a pre-fetched ``tool_statuses`` snapshot, the dialog must render
it immediately without spawning a fresh batch of background status-check
workers. Explicit user-initiated refresh must still spawn workers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.tool_config import (
    ToolStatusCheckWorker,
    ToolStatusDialog,
    ToolStatusEntry,
)


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


_EXPECTED_TOOL_COUNT: int = 6


def _make_prefetched_payload() -> dict[str, ToolStatusEntry]:
    """Build a complete prefetched payload matching the dialog's tool list.

    Returns:
        dict[str, ToolStatusEntry]: Mapping of every dialog-recognised tool
        ID to a deterministic :class:`ToolStatusEntry` so tests can assert
        on the rendered text without depending on the host environment.
    """
    return {
        "ghidra": {"available": True, "path": "C:/tools/ghidra", "message": "Ghidra installed"},
        "x64dbg": {"available": False, "path": None, "message": "x64dbg.exe not found"},
        "frida": {"available": True, "path": None, "message": "Frida 16.5 available"},
        "cutter": {"available": False, "path": None, "message": "Cutter executable not found"},
        "process": {"available": True, "path": None, "message": "Available (built-in)"},
        "binary": {"available": True, "path": None, "message": "Available (built-in)"},
    }


class _WorkerStartRecorder:
    """Counter for :meth:`ToolStatusCheckWorker.start` invocations.

    Used as a shared call counter while ``ToolStatusCheckWorker.start`` is
    monkeypatched with a free function that increments :attr:`calls`. This
    keeps the real ``QThread`` machinery from starting an actual OS thread
    in the test environment.
    """

    def __init__(self) -> None:
        self.calls: int = 0

    def increment(self) -> None:
        """Increment :attr:`calls` by one."""
        self.calls += 1


def _patch_worker_start(monkeypatch: pytest.MonkeyPatch, recorder: _WorkerStartRecorder) -> None:
    """Replace ``ToolStatusCheckWorker.start`` with a counting stub.

    The stub increments ``recorder.calls`` and returns ``None`` without
    invoking the underlying QThread machinery, so tests can assert on
    worker spawn counts deterministically and without launching real
    threads.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        recorder: Recorder whose ``increment`` method is called on every
            ``worker.start()`` invocation.
    """

    def _stub_start(_worker: ToolStatusCheckWorker) -> None:
        recorder.increment()

    monkeypatch.setattr(ToolStatusCheckWorker, "start", _stub_start)


@pytest.mark.usefixtures("qapp")
class TestToolStatusDialogPrefetch:
    """Behavioural tests covering prefetched-status reuse semantics."""

    @staticmethod
    def test_prefetched_data_skips_initial_worker_spawn(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Supplying ``tool_statuses`` must not spawn any status workers.

        The dialog should render the supplied snapshot directly and
        finish ``__init__`` with the Refresh button re-enabled and zero
        :class:`ToolStatusCheckWorker` threads started.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing
                ``ToolStatusCheckWorker.start``.
        """
        del qapp
        recorder = _WorkerStartRecorder()
        _patch_worker_start(monkeypatch, recorder)

        prefetched = _make_prefetched_payload()
        dialog = ToolStatusDialog(tool_statuses=prefetched)
        try:
            assert recorder.calls == 0
            assert dialog._refresh_btn.isEnabled()
            assert dialog._status_list.count() == _EXPECTED_TOOL_COUNT

            ghidra_text = dialog._status_list.item(0).text()
            assert "Ghidra" in ghidra_text
            assert "Ghidra installed" in ghidra_text
            assert "✓" in ghidra_text

            x64dbg_text = dialog._status_list.item(1).text()
            assert "x64dbg" in x64dbg_text
            assert "x64dbg.exe not found" in x64dbg_text
            assert "✗" in x64dbg_text
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_no_prefetched_data_spawns_workers(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Omitting ``tool_statuses`` must spawn one worker per tool row.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing
                ``ToolStatusCheckWorker.start``.
        """
        del qapp
        recorder = _WorkerStartRecorder()
        _patch_worker_start(monkeypatch, recorder)

        dialog = ToolStatusDialog()
        try:
            assert recorder.calls == _EXPECTED_TOOL_COUNT
            assert not dialog._refresh_btn.isEnabled()
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_refresh_button_spawns_workers_even_after_prefetch(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Refresh re-runs the workers even when initial prefetch was used.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing
                ``ToolStatusCheckWorker.start``.
        """
        del qapp
        recorder = _WorkerStartRecorder()
        _patch_worker_start(monkeypatch, recorder)

        prefetched = _make_prefetched_payload()
        dialog = ToolStatusDialog(tool_statuses=prefetched)
        try:
            assert recorder.calls == 0

            dialog._refresh_btn.click()

            assert recorder.calls == _EXPECTED_TOOL_COUNT
            assert not dialog._refresh_btn.isEnabled()
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_partial_prefetched_payload_renders_unknown_for_missing(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Tool rows absent from the prefetched payload render an unknown placeholder.

        The dialog still skips spawning workers because the call site
        explicitly requested a prefetched render; missing entries simply
        display a benign placeholder.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing
                ``ToolStatusCheckWorker.start``.
        """
        del qapp
        recorder = _WorkerStartRecorder()
        _patch_worker_start(monkeypatch, recorder)

        partial: dict[str, ToolStatusEntry] = {
            "ghidra": {"available": True, "path": "C:/tools/ghidra", "message": "Ghidra installed"},
        }
        dialog = ToolStatusDialog(tool_statuses=partial)
        try:
            assert recorder.calls == 0
            assert dialog._status_list.count() == _EXPECTED_TOOL_COUNT

            ghidra_text = dialog._status_list.item(0).text()
            assert "Ghidra installed" in ghidra_text

            x64dbg_text = dialog._status_list.item(1).text()
            assert "Status unknown" in x64dbg_text
        finally:
            dialog.deleteLater()
