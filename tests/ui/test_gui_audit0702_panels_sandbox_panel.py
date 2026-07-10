# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the 2026-07-02 GUI audit findings in ``sandbox_panel``.

Each test targets one audit finding and fails against the pre-fix behaviour:

* ``C6``: ``load_execution_report`` must read real ``TypedDict``/dict fields
  (dict access) instead of ``getattr`` on a plain ``dict``, which always fell
  through to placeholder defaults regardless of the report content.
* ``H11``: ``_cleanup`` must dispatch ``stop_pcap``/``destroy`` through the
  non-blocking ``run_bridge_coroutine_logged`` worker path instead of the
  blocking, untimed ``run_bridge_coroutine``, so panel teardown never freezes
  the GUI thread on a slow or unresponsive backend.
* ``H26``: ``_on_delete_snapshot_success`` must remove the row that matches
  ``self._pending_snapshot_id`` (the snapshot actually deleted), not whatever
  row happens to be selected when the async response arrives.
* ``M28``: ``_on_destroy_error`` must not force the panel into a destroyed
  UI state when the destroy RPC itself failed; it must resync from real
  status instead of orphaning an active sandbox instance.
* ``M29``: a restart whose destroy phase succeeded but whose create phase
  failed must reset ``sandbox_id`` and disable sandbox-active controls
  (the old instance really is gone); a restart whose destroy phase itself
  failed must leave that state untouched and only re-enable Restart.
* ``M61``: the panel's main vertical splitter must have
  ``childrenCollapsible() is False`` so neither pane can be dragged to zero
  size.
* ``L1``: the File Changes "Details" column must show descriptive content
  (a rename's previous path, or a byte-size fallback) instead of always
  echoing the raw ``size`` field regardless of operation.

All tests drive a real :class:`SandboxPanel` under an offscreen
``QApplication``; no widget behaviour is mocked. Bridge coroutine dispatch is
exercised either through real background-thread execution (H11) or by
capturing the exact coroutine/callback handed to the module-level bridge
runner (M29), matching the pattern used by the sibling VNC-connect audit
gate.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, cast

from PyQt6.QtWidgets import QApplication, QSplitter, QTreeWidgetItem

import intellicrack.ui.panels.sandbox_panel as sandbox_panel_mod
from intellicrack.sandbox.base import ExecutionReport
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    import pytest

    from intellicrack.bridges.sandbox_bridge import SandboxBridge
    from intellicrack.sandbox.base import FileChange, NetworkActivity, RegistryChange


_H11_BRIDGE_DELAY_S: float = 1.0
_H11_GUI_BLOCK_CEILING_S: float = 0.5
_H11_ASYNC_WAIT_CEILING_S: float = 5.0
_H11_POLL_INTERVAL_S: float = 0.02


class _DelayedCleanupBridge:
    """Fake sandbox bridge whose ``stop_pcap``/``destroy`` coroutines are slow.

    ``delay_seconds`` holds the wall-clock delay applied inside each
    coroutine; ``stop_pcap_calls`` and ``destroy_calls`` record the sandbox
    ids passed to each method, in call order.
    """

    def __init__(self, delay_seconds: float) -> None:
        """Initialise the fake bridge with a fixed per-call delay.

        Args:
            delay_seconds: Wall-clock delay applied inside each coroutine.
        """
        self.delay_seconds: float = delay_seconds
        self.stop_pcap_calls: list[str] = []
        self.destroy_calls: list[str] = []

    async def stop_pcap(self, sandbox_id: str) -> None:
        """Record the call and sleep, simulating a slow PCAP-stop RPC.

        Args:
            sandbox_id: Sandbox instance id passed by the caller.
        """
        self.stop_pcap_calls.append(sandbox_id)
        await asyncio.sleep(self.delay_seconds)

    async def destroy(self, sandbox_id: str) -> None:
        """Record the call and sleep, simulating a slow destroy RPC.

        Args:
            sandbox_id: Sandbox instance id passed by the caller.
        """
        self.destroy_calls.append(sandbox_id)
        await asyncio.sleep(self.delay_seconds)


def test_c6_load_execution_report_uses_real_field_values_not_getattr_defaults(
    qapp: QApplication,
) -> None:
    """``load_execution_report`` must render the real record fields.

    Pre-fix, every field was read via ``getattr(change, "field", default)``
    on a plain ``dict`` (``TypedDict`` instances have no attributes), so
    every call silently fell through to its default ("unknown"/""/0)
    regardless of the report's actual content; the network block also read
    nonexistent keys ("destination"/"port"/"data_size"). Post-fix, every
    field is read via dict access with the correct ``FileChange`` /
    ``RegistryChange`` / ``NetworkActivity`` keys, so the real values must
    appear in the trees.

    Args:
        qapp: Session QApplication fixture required for widget construction.
    """
    _ = qapp
    file_change: FileChange = {
        "path": "C:\\malware\\dropped.exe",
        "operation": "created",
        "old_path": None,
        "timestamp": "2026-07-01T00:00:00",
        "size": 2048,
    }
    registry_change: RegistryChange = {
        "key": "HKLM\\Software\\Evil\\Run",
        "value_name": "Updater",
        "operation": "modified",
        "value_type": "REG_SZ",
        "value_data": "C:\\malware\\dropped.exe",
        "timestamp": "2026-07-01T00:00:01",
    }
    network_activity: NetworkActivity = {
        "protocol": "tcp",
        "direction": "outbound",
        "local_address": "10.0.0.5",
        "local_port": 51000,
        "remote_address": "93.184.216.34",
        "remote_port": 443,
        "timestamp": "2026-07-01T00:00:02",
        "bytes_sent": 512,
        "bytes_received": 1024,
    }
    report = ExecutionReport(
        result="success",
        exit_code=0,
        stdout="",
        stderr="",
        duration_seconds=1.0,
        file_changes=[file_change],
        registry_changes=[registry_change],
        network_activity=[network_activity],
    )

    panel = SandboxPanel()
    panel.load_execution_report(report)

    file_item = panel._file_changes_tree.topLevelItem(0)
    assert file_item is not None
    assert file_item.text(0) == "created", "operation must come from the real record, not the getattr('unknown') default"
    assert file_item.text(1) == "C:\\malware\\dropped.exe", "path must come from the real record"

    reg_item = panel._registry_changes_tree.topLevelItem(0)
    assert reg_item is not None
    assert reg_item.text(0) == "modified"
    assert reg_item.text(1) == "HKLM\\Software\\Evil\\Run"
    assert reg_item.text(2) == "C:\\malware\\dropped.exe", "registry value must come from value_data, not the getattr default"

    net_item = panel._network_tree.topLevelItem(0)
    assert net_item is not None
    assert net_item.text(0) == "tcp"
    assert net_item.text(1) == "93.184.216.34", "network destination must come from remote_address, not the nonexistent 'destination' field"
    assert net_item.text(2) == "443"
    assert net_item.text(3) == "512/1024 bytes", (
        "network detail must combine bytes_sent/bytes_received, not the nonexistent 'data_size' field"
    )


def test_h11_cleanup_dispatches_async_and_does_not_block_gui_thread(
    qapp: QApplication,
) -> None:
    """``_cleanup`` must return promptly even though the bridge calls are slow.

    Pre-fix, ``_cleanup`` called the blocking ``run_bridge_coroutine`` with no
    ``timeout_s`` for both ``stop_pcap`` and ``destroy``, so the calling
    (GUI) thread sat inside ``future.result(timeout=None)`` for the full
    duration of both RPCs. Post-fix it dispatches both calls through
    ``run_bridge_coroutine_logged`` (the non-blocking worker-thread path), so
    ``_cleanup`` itself returns almost immediately regardless of how long the
    bridge takes, and the destroy phase still eventually runs once
    ``stop_pcap`` completes.

    Args:
        qapp: Session QApplication fixture used to pump queued signals
            delivered from the background worker thread.
    """
    panel = SandboxPanel()
    bridge = _DelayedCleanupBridge(delay_seconds=_H11_BRIDGE_DELAY_S)
    panel._bridge = cast("SandboxBridge", bridge)
    panel.sandbox_id = "sbx-h11"

    started = time.monotonic()
    panel._cleanup()
    elapsed = time.monotonic() - started

    assert elapsed < _H11_GUI_BLOCK_CEILING_S, (
        f"_cleanup blocked the calling thread for {elapsed:.3f}s; a bridge call "
        "inside _cleanup is still using the blocking run_bridge_coroutine path"
    )
    stop_deadline = time.monotonic() + _H11_ASYNC_WAIT_CEILING_S
    while not bridge.stop_pcap_calls and time.monotonic() < stop_deadline:
        qapp.processEvents()
        time.sleep(_H11_POLL_INTERVAL_S)
    assert bridge.stop_pcap_calls == ["sbx-h11"], "stop_pcap was not dispatched"

    deadline = time.monotonic() + _H11_ASYNC_WAIT_CEILING_S
    while not bridge.destroy_calls and time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(_H11_POLL_INTERVAL_S)

    assert bridge.destroy_calls == ["sbx-h11"], "destroy phase never ran asynchronously after stop_pcap completed"


def test_h26_delete_snapshot_removes_row_by_pending_id_not_by_selection(
    qapp: QApplication,
) -> None:
    """The deleted snapshot's row must be removed, not whatever row is selected.

    Pre-fix, ``_on_delete_snapshot_success`` re-queried the tree's *current
    selection* at completion time and removed that row, so if the user
    changed their selection while the async delete was in flight, the wrong
    row was removed from the UI. Post-fix it looks up the row by
    ``self._pending_snapshot_id`` (the snapshot that was actually deleted).

    Args:
        qapp: Session QApplication fixture required for widget construction.
    """
    _ = qapp
    panel = SandboxPanel()
    tree = panel._snapshots_tree
    item_a = QTreeWidgetItem(["snap-a", "Snapshot A", "2026-07-01"])
    item_b = QTreeWidgetItem(["snap-b", "Snapshot B", "2026-07-02"])
    tree.addTopLevelItem(item_a)
    tree.addTopLevelItem(item_b)

    tree.setCurrentItem(item_b)
    assert tree.currentItem() is item_b, "test premise: selection has moved to snap-b"

    panel._pending_snapshot_id = "snap-a"
    panel.delete_snap_btn.setEnabled(False)

    panel._on_delete_snapshot_success(None)

    remaining = [tree.topLevelItem(i).text(0) for i in range(tree.topLevelItemCount())]
    assert remaining == ["snap-b"], f"expected only the deleted snap-a to be removed, got remaining rows {remaining}"
    assert panel.delete_snap_btn.isEnabled()


def test_m28_destroy_error_preserves_active_state_for_orphaned_sandbox(
    qapp: QApplication,
) -> None:
    """A failed destroy must not force the panel into a fabricated destroyed state.

    Pre-fix, ``_on_destroy_error`` cleared ``sandbox_id``, forced the status
    indicator to "Inactive", disabled every sandbox control, and stopped the
    poll timer -- identical to the success path -- even though the backend
    instance (and any active PCAP capture) is still alive. Post-fix it keeps
    ``sandbox_id`` and the active controls intact and resyncs from a real
    status poll instead of assuming success.

    Args:
        qapp: Session QApplication fixture required for widget construction.
    """
    _ = qapp
    panel = SandboxPanel()
    panel.sandbox_id = "sbx-orphan"
    panel._pcap_capture_id = "pcap-active"
    panel._set_sandbox_controls_active(active=True)
    panel._status_indicator.setText("Active")
    panel._status_poll_timer.start(5000)

    try:
        panel._on_destroy_error(RuntimeError("bridge unreachable"))

        assert panel.sandbox_id == "sbx-orphan", "destroy failure must not clear sandbox_id and orphan the still-running instance"
        assert panel._status_indicator.text() != "Inactive", "status must not be forced to Inactive on a failed destroy"
        assert panel.pcap_btn.isEnabled(), "PCAP control must remain usable so an active capture can still be stopped"
        assert panel.screenshot_btn.isEnabled(), "controls must not be blanket-disabled on destroy failure"
        assert panel._status_poll_timer.isActive(), "poll timer must keep running to resync real state"
    finally:
        panel._status_poll_timer.stop()


def test_m29_restart_create_failure_after_destroy_clears_stale_sandbox_id(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A restart whose destroy succeeded but whose create failed must reset state.

    Pre-fix, the shared ``_on_restart_error`` handler only re-enabled the
    Restart button in every case; if the destroy phase had already
    succeeded (the old instance is really gone) and the subsequent create
    failed, ``sandbox_id`` kept pointing at the destroyed instance while
    every sandbox-active control (Screenshot, PCAP, Execute, ...) stayed
    enabled. Post-fix, ``_on_restart_error`` checks
    ``self._restart_pending_destroy`` and routes a post-destroy create
    failure through ``_finish_restart_after_destroy_only``, which clears
    ``sandbox_id``, disables the active controls, stops the poll timer, and
    emits ``tool_closed``.

    Args:
        qapp: Session QApplication fixture required for widget construction.
        monkeypatch: Fixture used to intercept the create-phase dispatch and
            fail it synchronously and deterministically.
    """
    _ = qapp

    class _FakeRestartBridge:
        """Fake bridge exposing only the coroutine-returning methods restart uses."""

        async def create(self, *, sandbox_type: object, **kwargs: object) -> dict[str, object]:
            """Return an empty result; never actually awaited by the test.

            Args:
                sandbox_type: Sandbox type requested (ignored).
                **kwargs: Remaining creation config (ignored).

            Returns:
                dict[str, object]: An empty placeholder result.
            """
            del sandbox_type, kwargs
            return {}

    def _immediate_create_failure(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None,
        on_error: Callable[[object], None] | None,
        parent: object,
        **_kwargs: object,
    ) -> None:
        """Close the create coroutine and invoke ``on_error`` synchronously.

        Args:
            coro: Bridge coroutine that would run on the worker (unused).
            on_success: Success callback (unused here).
            on_error: Error callback invoked with a synthetic failure.
            parent: Qt parent (unused here).
            **_kwargs: Structured logging context (ignored).
        """
        _ = (on_success, parent, _kwargs)
        coro.close()
        if on_error is not None:
            on_error(RuntimeError("create failed"))

    monkeypatch.setattr(sandbox_panel_mod, "run_bridge_coroutine_logged", _immediate_create_failure)

    panel = SandboxPanel()
    panel._bridge = cast("SandboxBridge", _FakeRestartBridge())
    panel.sandbox_id = "old-sbx"
    panel._set_sandbox_controls_active(active=True)
    panel._status_indicator.setText("Active")
    panel._status_poll_timer.start(5000)

    closed: list[bool] = []
    _ = panel.tool_closed.connect(lambda: closed.append(True))

    panel._on_restart_destroy_success(None)

    assert panel.sandbox_id is None, "sandbox_id must be cleared once the create phase fails after a successful destroy"
    assert panel._status_indicator.text() == "Inactive"
    assert not panel.destroy_btn.isEnabled()
    assert not panel.pcap_btn.isEnabled()
    assert not panel._status_poll_timer.isActive()
    assert closed == [True], "tool_closed must be emitted once the destroyed instance is not replaced"


def test_m29_restart_destroy_phase_failure_only_reenables_restart_button(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A restart whose destroy phase itself fails must leave state untouched.

    Contrasts with the post-destroy create-failure case: here the original
    instance was never destroyed, so ``sandbox_id`` and the active controls
    must remain exactly as they were, and only the Restart button should be
    re-enabled for a retry.

    Args:
        qapp: Session QApplication fixture required for widget construction.
        monkeypatch: Fixture used to intercept the destroy-phase dispatch
            and fail it synchronously and deterministically.
    """
    _ = qapp

    def _immediate_destroy_failure(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None,
        on_error: Callable[[object], None] | None,
        parent: object,
        **_kwargs: object,
    ) -> None:
        """Close the destroy coroutine and invoke ``on_error`` synchronously.

        Args:
            coro: Bridge coroutine that would run on the worker (unused).
            on_success: Success callback (unused here).
            on_error: Error callback invoked with a synthetic failure.
            parent: Qt parent (unused here).
            **_kwargs: Structured logging context (ignored).
        """
        _ = (on_success, parent, _kwargs)
        coro.close()
        if on_error is not None:
            on_error(RuntimeError("destroy failed"))

    monkeypatch.setattr(sandbox_panel_mod, "run_bridge_coroutine_logged", _immediate_destroy_failure)

    panel = SandboxPanel()
    panel._bridge = cast("SandboxBridge", _DelayedCleanupBridge(delay_seconds=0.0))
    panel.sandbox_id = "old-sbx"
    panel._set_sandbox_controls_active(active=True)
    panel._status_indicator.setText("Active")
    panel._status_poll_timer.start(5000)

    try:
        panel._on_restart()

        assert panel.sandbox_id == "old-sbx", "a destroy-phase failure must not touch sandbox_id"
        assert panel._status_indicator.text() == "Active"
        assert panel.destroy_btn.isEnabled()
        assert panel.restart_btn.isEnabled(), "Restart must be re-enabled so the user can retry"
        assert panel._status_poll_timer.isActive()
    finally:
        panel._status_poll_timer.stop()


def test_m61_main_splitter_children_not_collapsible(qapp: QApplication) -> None:
    """The main vertical splitter must not allow either pane to collapse to zero.

    Pre-fix, ``main_splitter`` was constructed without
    ``setChildrenCollapsible(False)``, so dragging the handle to either
    extreme could hide the entire 15-tab output area (including the live
    Console log and VM Display) with only a thin, hard-to-grab sliver left.
    Post-fix, ``childrenCollapsible()`` is ``False`` and Qt clamps
    ``moveSplitter`` to each pane's minimum size instead of allowing zero.

    Args:
        qapp: Session QApplication fixture required for widget construction.
    """
    _ = qapp
    panel = SandboxPanel()
    panel.resize(900, 700)
    panel.show()
    QApplication.processEvents()

    splitter = panel.findChild(QSplitter)
    assert splitter is not None, "panel must contain the main splitter"
    assert splitter.childrenCollapsible() is False, "main_splitter must disable child collapsing, matching sibling panels"

    before = splitter.sizes()
    assert len(before) == 2
    assert all(size > 0 for size in before), "test premise: both panes start with nonzero size"

    splitter.moveSplitter(0, 1)
    QApplication.processEvents()
    after = splitter.sizes()

    assert after[0] > 0, "top pane (exec controls) collapsed to zero height on a drag-to-top"
    assert after[1] > 0, "bottom pane (output tabs) collapsed to zero height on a drag-to-top"

    panel.hide()


def test_l1_file_change_details_column_shows_rename_or_size_not_bare_size(
    qapp: QApplication,
) -> None:
    """The "Details" column must describe the change, not always echo ``size``.

    Pre-fix, ``_populate_file_changes`` filled the third column with
    ``change.get("size", "")`` for every row regardless of operation, so a
    rename showed a raw byte count under a column headed "Details" instead
    of anything descriptive. Post-fix, a rename shows its previous path and
    a non-rename shows a labelled byte count.

    Args:
        qapp: Session QApplication fixture required for widget construction.
    """
    _ = qapp
    panel = SandboxPanel()
    file_changes: list[dict[str, object]] = [
        {
            "path": "C:\\Windows\\Temp\\final.bin",
            "operation": "renamed",
            "old_path": "C:\\Windows\\Temp\\stage.bin",
            "timestamp": "2026-07-01T00:00:00",
            "size": 8192,
        },
        {
            "path": "C:\\Users\\analyst\\AppData\\drop.exe",
            "operation": "created",
            "old_path": None,
            "timestamp": "2026-07-01T00:00:01",
            "size": 4096,
        },
    ]

    panel._populate_file_changes(file_changes)

    tree = panel._file_changes_tree
    assert tree.topLevelItemCount() == 2

    rename_item = tree.topLevelItem(0)
    created_item = tree.topLevelItem(1)
    assert rename_item is not None
    assert created_item is not None

    assert rename_item.text(2) == "renamed from C:\\Windows\\Temp\\stage.bin", (
        "a rename's Details column must show the previous path, not a bare size"
    )
    assert created_item.text(2) == "4096 bytes", "a non-rename's Details column must show a labelled byte count, not a bare number"
    assert rename_item.text(2) != str(file_changes[0]["size"]), "Details must not still be the raw, unlabelled size for a rename"
