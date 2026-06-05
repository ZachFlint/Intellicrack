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


_EXPECTED_ROWS: tuple[str, ...] = (
    "✓  Ghidra - Ghidra installed",
    "✗  x64dbg - x64dbg.exe not found",
    "✓  Frida - Frida 16.5 available",
    "✗  Cutter - Cutter executable not found",
    "✓  Process Control - Available (built-in)",
    "✓  Binary Operations - Available (built-in)",
)


def _assert_prefetched_render(dialog: ToolStatusDialog) -> None:
    """Assert a fully prefetched dialog renders every row exactly without spawning workers.

    Inspects the dialog's *real* internal ``_status_workers`` list to prove
    no :class:`ToolStatusCheckWorker` was constructed or started (the
    prefetch path must never append to it), without faking ``QThread.start``.
    Then asserts the complete rendered text of all six rows, row by row, in
    canonical tool order against an independently constructed expectation,
    covering the status glyph, display name, and message for each tool, and
    cross-checks each glyph against the supplied availability flag. A
    scrambled order, a blanked row, a wrong glyph, or a stray spawned worker
    would all fail.

    Args:
        dialog: ToolStatusDialog instance under test.
    """
    assert dialog._status_workers == []
    assert dialog._refresh_btn.isEnabled()
    assert dialog._status_list.count() == _EXPECTED_TOOL_COUNT

    rendered = [dialog._status_list.item(row).text() for row in range(dialog._status_list.count())]
    assert rendered == list(_EXPECTED_ROWS)

    payload = _make_prefetched_payload()
    expected_glyph_by_id = {tool_id: ("✓" if entry["available"] else "✗") for tool_id, entry in payload.items()}
    for row, (display_name, tool_id, _category) in enumerate(ToolStatusDialog._tool_rows()):
        text = dialog._status_list.item(row).text()
        assert text.startswith(expected_glyph_by_id[tool_id]), (tool_id, text)
        assert display_name in text
        assert payload[tool_id]["message"] in text

    assert dialog._status_list.currentRow() == 0


def _assert_partial_prefetched_render(dialog: ToolStatusDialog) -> None:
    """Assert a partial prefetched dialog renders unknown for missing rows.

    Verifies no real worker was spawned (the ``_status_workers`` list stays
    empty), the present row renders with its checkmark glyph and message, and
    every absent tool row falls back to the canonical unknown placeholder in
    canonical order.

    Args:
        dialog: ToolStatusDialog instance under test.
    """
    assert dialog._status_workers == []
    assert dialog._status_list.count() == _EXPECTED_TOOL_COUNT

    rendered = [dialog._status_list.item(row).text() for row in range(dialog._status_list.count())]
    assert rendered == [
        "✓  Ghidra - Ghidra installed",
        "... x64dbg - Status unknown",
        "... Frida - Status unknown",
        "... Cutter - Status unknown",
        "... Process Control - Status unknown",
        "... Binary Operations - Status unknown",
    ]


def _assert_spawned_workers(dialog: ToolStatusDialog, recorder: _WorkerStartRecorder) -> None:
    """Assert ``_refresh_status`` built one real worker per tool in canonical order.

    Args:
        dialog: ToolStatusDialog instance whose refresh just ran.
        recorder: Recorder tracking ``ToolStatusCheckWorker.start`` calls.
    """
    assert recorder.calls == _EXPECTED_TOOL_COUNT
    assert not dialog._refresh_btn.isEnabled()
    assert len(dialog._status_workers) == _EXPECTED_TOOL_COUNT
    assert all(isinstance(worker, ToolStatusCheckWorker) for worker in dialog._status_workers)
    spawned_ids = [worker._tool_id for worker in dialog._status_workers]
    assert spawned_ids == [tool_id for _name, tool_id, _category in ToolStatusDialog._tool_rows()]


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
    def test_prefetched_data_skips_initial_worker_spawn(qapp: QApplication) -> None:
        """Supplying ``tool_statuses`` must not spawn any status workers.

        Drives the real :class:`ToolStatusDialog` end to end with no faked
        ``QThread.start``: the dialog must render the supplied snapshot
        directly, leave its real ``_status_workers`` list empty (no worker
        ever constructed or started), finish ``__init__`` with the Refresh
        button re-enabled, and render all six rows exactly.

        Args:
            qapp: QApplication fixture from conftest.
        """
        del qapp
        prefetched = _make_prefetched_payload()
        dialog = ToolStatusDialog(tool_statuses=prefetched)
        try:
            _assert_prefetched_render(dialog)
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_no_prefetched_data_spawns_workers(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Omitting ``tool_statuses`` must spawn one real worker per tool row in order.

        Stubs only ``QThread.start`` (framework plumbing, not the operation
        under test) so no OS thread launches and the dialog's real
        ``_status_workers`` list is never cleared by async completion, making
        the assertion deterministic. Asserts that ``_refresh_status``
        constructed exactly one real :class:`ToolStatusCheckWorker` per tool
        in canonical order, that ``start`` was invoked once per worker, and
        that the Refresh button is disabled while checks are pending.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for stubbing
                ``ToolStatusCheckWorker.start``.
        """
        del qapp
        recorder = _WorkerStartRecorder()
        _patch_worker_start(monkeypatch, recorder)

        dialog = ToolStatusDialog()
        try:
            _assert_spawned_workers(dialog, recorder)
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
            assert dialog._status_workers == []

            dialog._refresh_btn.click()

            _assert_spawned_workers(dialog, recorder)
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_partial_prefetched_payload_renders_unknown_for_missing(qapp: QApplication) -> None:
        """Tool rows absent from the prefetched payload render an unknown placeholder.

        The dialog still skips spawning workers because the call site
        explicitly requested a prefetched render; missing entries simply
        display a benign placeholder. Verified against the real
        ``_status_workers`` list rather than a faked ``QThread.start``.

        Args:
            qapp: QApplication fixture from conftest.
        """
        del qapp
        partial: dict[str, ToolStatusEntry] = {
            "ghidra": {"available": True, "path": "C:/tools/ghidra", "message": "Ghidra installed"},
        }
        dialog = ToolStatusDialog(tool_statuses=partial)
        try:
            _assert_partial_prefetched_render(dialog)
        finally:
            dialog.deleteLater()
