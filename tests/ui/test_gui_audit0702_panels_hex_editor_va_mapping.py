# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for GUI audit findings M12 and M13 in ``hex_editor.va_mapping``.

M12 -- ``_on_goto_va`` and ``_on_cursor_offset_to_va`` called the **blocking**
``run_bridge_coroutine`` variant directly from synchronous Qt slots
(``goto_btn.clicked`` / ``offset_lookup_btn.clicked``), instead of the
non-blocking ``run_bridge_coroutine_logged`` used everywhere else in this
file. ``run_bridge_coroutine`` calls ``future.result()`` on the calling
thread, so a slow bridge round trip froze the whole GUI. The fix routes both
handlers through ``run_bridge_coroutine_logged``, delivering the result via
``_on_va_to_file_offset_resolved``/``_on_file_offset_to_va_resolved`` and
failures via ``_on_va_conversion_error``/``_on_cursor_offset_conversion_error``
on a queued Qt signal.

M13 -- ``_on_open_performance_settings`` used the same blocking
``run_bridge_coroutine`` for ``get_memory_usage()`` and, after the dialog was
accepted, for ``set_chunk_size()``/``set_memory_budget()``, stalling the GUI
thread on every one of the three RPCs. The fix splits the method into
``_on_memory_usage_ready`` (dispatched via ``run_bridge_coroutine_logged``
after ``get_memory_usage`` resolves) and a chained
``_on_chunk_size_applied`` -> ``_on_memory_budget_applied`` sequence, each
hop dispatched via ``run_bridge_coroutine_logged``.

Every test below drives the real ``VaMappingMixin`` handlers on a minimal
host against a real (subclassed) ``HexEditorBridge``, injecting an
artificial ``asyncio.sleep`` delay into the RPCs under test so the
non-blocking dispatch contract can be measured directly: the handler must
return to its caller in a small fraction of the delay (proving it did not
wait on ``future.result()`` inline) and every observable side effect --
navigation, status text, applied chunk/budget, the success dialog -- must
remain unset until the Qt event loop is pumped and the queued result signal
fires.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, ClassVar

import pytest
from PyQt6.QtWidgets import QDialog, QLabel, QLineEdit, QMessageBox, QTreeWidget, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor import va_mapping as va_mapping_module
from intellicrack.ui.panels.hex_editor.va_mapping import VaMappingMixin


if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QApplication


_DELAY_S: float = 0.4
"""Artificial async delay injected into the fake bridge RPCs, in seconds."""

_RETURN_BUDGET_S: float = _DELAY_S / 2
"""Maximum wall-clock time a non-blocking dispatch may take to return."""

_VA_BASE: int = 0x1000
"""Deterministic offset used by ``_DelayedVaBridge`` to map VA <-> file offset."""

_USAGE_BYTES: int = 5 * 1024 * 1024
_CHUNK_BYTES: int = 256 * 1024
_BUDGET_BYTES: int = 64 * 1024 * 1024
_SELECTED_CHUNK_KB: int = 4096
_SELECTED_BUDGET_MB: int = 512


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float) -> bool:
    """Pump the Qt event loop until ``predicate()`` is true or the timeout elapses.

    Cross-thread results delivered via ``run_bridge_coroutine_logged`` /
    ``BridgeCallWorker`` signals from the background asyncio thread only
    reach their Qt slots while the main-thread event loop is processing
    events, so tests must pump the loop while waiting for a handler's
    delayed side effect.

    Args:
        qapp: The active QApplication whose event loop is pumped.
        predicate: Zero-argument callable polled after each pump.
        timeout_s: Maximum number of seconds to wait.

    Returns:
        bool: ``True`` if ``predicate()`` became true before the timeout.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(0.02)
    return predicate()


class _DelayedVaBridge(HexEditorBridge):
    """``HexEditorBridge`` whose VA/performance RPCs impose an artificial delay.

    Lets a test distinguish a non-blocking dispatch (the caller returns well
    before the coroutine finishes) from a blocking one (the caller only
    returns once the coroutine, including the delay, has completed). Every
    overridden method is self-contained -- it does not touch ``self.document``
    -- so the bridge can be exercised without a real hex document attached.

    Attributes:
        applied_chunk_bytes: Chunk size, in bytes, most recently passed to
            :meth:`set_chunk_size`, or ``None`` if never called.
        applied_budget_bytes: Memory budget, in bytes, most recently passed
            to :meth:`set_memory_budget`, or ``None`` if never called.
    """

    applied_chunk_bytes: int | None
    applied_budget_bytes: int | None

    def __init__(self, delay_s: float) -> None:
        """Initialise the bridge with the configured artificial delay.

        Args:
            delay_s: Number of seconds each overridden RPC sleeps for before
                returning its deterministic result.
        """
        super().__init__()
        self._delay_s: float = delay_s
        self.applied_chunk_bytes: int | None = None
        self.applied_budget_bytes: int | None = None

    async def va_to_file_offset(self, va: int) -> int | None:
        """Sleep, then deterministically map a virtual address to a file offset.

        Args:
            va: Virtual address to convert.

        Returns:
            int | None: ``va - _VA_BASE``.
        """
        await asyncio.sleep(self._delay_s)
        return va - _VA_BASE

    async def file_offset_to_va(self, offset: int) -> int | None:
        """Sleep, then deterministically map a file offset to a virtual address.

        Args:
            offset: File offset to convert.

        Returns:
            int | None: ``offset + _VA_BASE``.
        """
        await asyncio.sleep(self._delay_s)
        return offset + _VA_BASE

    async def get_memory_usage(self) -> dict[str, int]:
        """Sleep, then return a fixed memory-usage estimate.

        Returns:
            dict[str, int]: Fixed ``usage_bytes``/``chunk_size``/``memory_budget`` payload.
        """
        await asyncio.sleep(self._delay_s)
        return {"usage_bytes": _USAGE_BYTES, "chunk_size": _CHUNK_BYTES, "memory_budget": _BUDGET_BYTES}

    async def set_chunk_size(self, size_bytes: int) -> bool:
        """Sleep, then record the requested chunk size.

        Args:
            size_bytes: Chunk size, in bytes, requested by the caller.

        Returns:
            bool: Always ``True``.
        """
        await asyncio.sleep(self._delay_s)
        self.applied_chunk_bytes = size_bytes
        return True

    async def set_memory_budget(self, budget_bytes: int) -> bool:
        """Sleep, then record the requested memory budget.

        Args:
            budget_bytes: Memory budget, in bytes, requested by the caller.

        Returns:
            bool: Always ``True``.
        """
        await asyncio.sleep(self._delay_s)
        self.applied_budget_bytes = budget_bytes
        return True


class _FailingVaBridge(HexEditorBridge):
    """``HexEditorBridge`` whose ``va_to_file_offset`` raises after an artificial delay.

    Used to prove a failed RPC is surfaced through the async ``on_error``
    callback path rather than by blocking the caller until the failure
    occurs and raising/handling it inline.
    """

    def __init__(self, delay_s: float) -> None:
        """Initialise the bridge with the configured artificial delay.

        Args:
            delay_s: Number of seconds ``va_to_file_offset`` sleeps for
                before raising.
        """
        super().__init__()
        self._delay_s: float = delay_s

    async def va_to_file_offset(self, va: int) -> int | None:
        """Sleep, then raise a simulated RPC failure.

        Args:
            va: Virtual address to convert (unused; failure is unconditional).

        Returns:
            int | None: Never returns; always raises.

        Raises:
            RuntimeError: Always, after the artificial delay.
        """
        del va
        await asyncio.sleep(self._delay_s)
        msg = "simulated va_to_file_offset failure"
        raise RuntimeError(msg)


class _FakeHexWidget:
    """Minimal hex-view stand-in exposing only ``goto_offset`` and ``_cursor_offset``.

    Attributes:
        goto_calls: File offsets passed to :meth:`goto_offset`, in call order.
    """

    goto_calls: list[int]

    def __init__(self, cursor_offset: int | None = None) -> None:
        """Initialise the fake widget with an optional starting cursor offset.

        Args:
            cursor_offset: Value exposed via ``self._cursor_offset``, mirroring
                the real hex widget's private cursor-position attribute.
        """
        self._cursor_offset = cursor_offset
        self.goto_calls: list[int] = []

    def goto_offset(self, offset: int) -> None:
        """Record a navigation request instead of moving a real viewport.

        Args:
            offset: File offset the caller requested navigation to.
        """
        self.goto_calls.append(offset)


class _VaMappingHost(VaMappingMixin):
    """Minimal host exposing only the state ``VaMappingMixin`` handlers touch.

    Reproduces the subset of ``HexEditorPanel`` state used by
    ``_on_goto_va``, ``_on_cursor_offset_to_va``, and
    ``_on_open_performance_settings`` without constructing the full panel.
    The bridge and hex-view attributes are set post-construction by each
    test; ``_va_mappings_tree``, ``_va_file_offset_edit``,
    ``_va_address_edit``, and ``_va_length_edit`` stay ``None`` because none
    of the three handlers under test touch them, while ``_va_goto_edit`` and
    ``_va_status_label`` are real widgets the handlers read from and write to.

    Attributes:
        document: Backing document; always ``None`` (unused by these handlers).
    """

    document: object | None
    _bridge: HexEditorBridge | None
    _hex_widget: _FakeHexWidget | None
    _va_mappings_tree: QTreeWidget | None
    _va_file_offset_edit: QLineEdit | None
    _va_address_edit: QLineEdit | None
    _va_length_edit: QLineEdit | None
    _va_goto_edit: QLineEdit | None
    _va_status_label: QLabel | None

    def __init__(self) -> None:
        """Initialise empty document/bridge/widget state and real Qt inputs."""
        self.document: object | None = None
        self._bridge: HexEditorBridge | None = None
        self._hex_widget: _FakeHexWidget | None = None
        self._va_mappings_tree: QTreeWidget | None = None
        self._va_file_offset_edit: QLineEdit | None = None
        self._va_address_edit: QLineEdit | None = None
        self._va_length_edit: QLineEdit | None = None
        self._va_goto_edit: QLineEdit | None = QLineEdit()
        self._va_status_label: QLabel | None = QLabel("")


class _DialogRecorder:
    """Records ``show_warning``/``show_info`` invocations without a real modal.

    Attributes:
        warning_calls: ``(title, message)`` pairs recorded from :meth:`warning`.
        info_calls: ``(title, message)`` pairs recorded from :meth:`info`.
    """

    warning_calls: list[tuple[str, str]]
    info_calls: list[tuple[str, str]]

    def __init__(self) -> None:
        """Initialise empty warning/info call ledgers."""
        self.warning_calls: list[tuple[str, str]] = []
        self.info_calls: list[tuple[str, str]] = []

    def warning(
        self,
        parent: QWidget | None,
        title: str,
        message: str,
        *,
        exc: BaseException | None = None,
    ) -> QMessageBox.StandardButton:
        """Record a ``show_warning`` call instead of showing a real dialog.

        Args:
            parent: Parent widget for the warning dialog (unused; not shown).
            title: Dialog title.
            message: Dialog message body.
            exc: Optional exception associated with the warning (unused).

        Returns:
            QMessageBox.StandardButton: A fixed ``Ok`` response, mirroring
                the dismissal a real dialog would eventually return.
        """
        del parent, exc
        self.warning_calls.append((title, message))
        return QMessageBox.StandardButton.Ok

    def info(self, parent: QWidget | None, title: str, message: str) -> QMessageBox.StandardButton:
        """Record a ``show_info`` call instead of showing a real dialog.

        Args:
            parent: Parent widget for the info dialog (unused; not shown).
            title: Dialog title.
            message: Dialog message body.

        Returns:
            QMessageBox.StandardButton: A fixed ``Ok`` response, mirroring
                the dismissal a real dialog would eventually return.
        """
        del parent
        self.info_calls.append((title, message))
        return QMessageBox.StandardButton.Ok


@pytest.fixture
def dialog_recorder(monkeypatch: pytest.MonkeyPatch) -> _DialogRecorder:
    """Intercept ``show_warning``/``show_info`` in ``va_mapping`` for this test.

    Args:
        monkeypatch: Pytest fixture used to replace the module-level dialog
            helpers so no real modal ``QMessageBox`` is spawned.

    Returns:
        _DialogRecorder: Recorder capturing every warning/info invocation.
    """
    recorder = _DialogRecorder()
    monkeypatch.setattr(va_mapping_module, "show_warning", recorder.warning)
    monkeypatch.setattr(va_mapping_module, "show_info", recorder.info)
    return recorder


class _StubLargeFileSettingsDialog:
    """Stand-in for ``LargeFileSettingsDialog`` that accepts immediately.

    Avoids driving a real modal ``QDialog.exec()`` event loop inside a unit
    test. Reports fixed ``chunk_size_kb`` / ``memory_budget_mb`` selections
    on acceptance and records every construction so tests can observe
    exactly when (if at all) the dialog was presented.

    Attributes:
        instances: Every constructed instance, in construction order.
        current_chunk_kb: The "current" chunk size passed by the caller.
        current_budget_mb: The "current" memory budget passed by the caller.
        current_usage_mb: The "current" memory usage passed by the caller.
        chunk_size_kb: Fixed chunk size, in KB, reported as selected.
        memory_budget_mb: Fixed memory budget, in MB, reported as selected.
    """

    instances: ClassVar[list[_StubLargeFileSettingsDialog]] = []
    current_chunk_kb: int
    current_budget_mb: int
    current_usage_mb: float
    chunk_size_kb: int
    memory_budget_mb: int

    def __init__(
        self,
        current_chunk_kb: int,
        current_budget_mb: int,
        current_usage_mb: float,
        parent: QWidget | None = None,
    ) -> None:
        """Record the constructor arguments and select fixed replacement values.

        Args:
            current_chunk_kb: Current chunk size, in KB, computed by the caller.
            current_budget_mb: Current memory budget, in MB, computed by the caller.
            current_usage_mb: Current memory usage estimate, in MB, computed
                by the caller.
            parent: Parent widget (unused; no real dialog is shown).
        """
        del parent
        self.current_chunk_kb = current_chunk_kb
        self.current_budget_mb = current_budget_mb
        self.current_usage_mb = current_usage_mb
        self.chunk_size_kb = _SELECTED_CHUNK_KB
        self.memory_budget_mb = _SELECTED_BUDGET_MB
        type(self).instances.append(self)

    def exec(self) -> int:
        """Report acceptance immediately, without a real modal Qt event loop.

        Returns:
            int: ``QDialog.DialogCode.Accepted``.
        """
        return int(QDialog.DialogCode.Accepted)


@pytest.fixture
def stub_dialog_class(monkeypatch: pytest.MonkeyPatch) -> type[_StubLargeFileSettingsDialog]:
    """Patch ``va_mapping``'s ``LargeFileSettingsDialog`` with the non-modal stub.

    Args:
        monkeypatch: Pytest fixture used to replace the module-level dialog
            class reference so no real modal ``QDialog.exec()`` event loop
            is entered.

    Returns:
        type[_StubLargeFileSettingsDialog]: The stub class now installed in
            place of the real dialog, with its instance ledger cleared.
    """
    _StubLargeFileSettingsDialog.instances.clear()
    monkeypatch.setattr(va_mapping_module, "LargeFileSettingsDialog", _StubLargeFileSettingsDialog)
    return _StubLargeFileSettingsDialog


def test_m12_on_goto_va_dispatches_non_blocking_and_resolves_via_queued_signal(
    qapp: QApplication,
    dialog_recorder: _DialogRecorder,
) -> None:
    """``_on_goto_va`` must return before the delayed ``va_to_file_offset`` RPC finishes.

    Pre-fix, the handler called the blocking
    ``run_bridge_coroutine(bridge.va_to_file_offset(va))``, which invokes
    ``future.result()`` on the calling (GUI) thread and would not return --
    nor navigate the hex view -- until the full artificial delay had
    elapsed. Post-fix, the RPC is dispatched via ``run_bridge_coroutine_logged``
    onto a background ``BridgeCallWorker`` thread, so the handler returns in
    a small fraction of the delay and navigation only happens once the Qt
    event loop delivers the queued result signal.

    Args:
        qapp: The shared offscreen QApplication fixture.
        dialog_recorder: Intercepts ``show_warning``/``show_info`` so no
            real modal dialog is spawned; not expected to fire here.
    """
    del dialog_recorder
    bridge = _DelayedVaBridge(_DELAY_S)
    host = _VaMappingHost()
    host._bridge = bridge
    hex_widget = _FakeHexWidget()
    host._hex_widget = hex_widget
    assert host._va_goto_edit is not None
    host._va_goto_edit.setText("2000")

    start = time.monotonic()
    host._on_goto_va()
    elapsed = time.monotonic() - start

    assert elapsed < _RETURN_BUDGET_S, (
        f"_on_goto_va blocked the calling thread for {elapsed:.3f}s waiting on a {_DELAY_S}s "
        "va_to_file_offset RPC instead of dispatching it to a background worker"
    )
    assert hex_widget.goto_calls == [], (
        "the hex view was already navigated before _on_goto_va returned; va_to_file_offset is "
        "being awaited synchronously on the calling thread"
    )
    assert host._va_status_label is not None
    assert not host._va_status_label.text()

    completed = _pump_until(qapp, lambda: bool(hex_widget.goto_calls), timeout_s=_DELAY_S + 5.0)
    assert completed, "goto_offset was never invoked after the delayed va_to_file_offset resolved"

    expected_offset = 0x2000 - _VA_BASE
    assert hex_widget.goto_calls == [expected_offset]
    assert host._va_status_label.text() == f"0x2000 -> file offset 0x{expected_offset:X}"


def test_m12_on_cursor_offset_to_va_dispatches_non_blocking_and_resolves_via_queued_signal(
    qapp: QApplication,
    dialog_recorder: _DialogRecorder,
) -> None:
    """``_on_cursor_offset_to_va`` must return before the delayed ``file_offset_to_va`` RPC finishes.

    Pre-fix, the handler called the blocking
    ``run_bridge_coroutine(bridge.file_offset_to_va(cursor_offset))`` directly
    on the GUI thread, so the status label would not update -- and the call
    would not return -- until the full artificial delay had elapsed.
    Post-fix, the RPC is dispatched via ``run_bridge_coroutine_logged``, so
    the handler returns in a small fraction of the delay and the status
    label only updates once the queued result signal fires.

    Args:
        qapp: The shared offscreen QApplication fixture.
        dialog_recorder: Intercepts ``show_warning``/``show_info`` so no
            real modal dialog is spawned; not expected to fire here.
    """
    del dialog_recorder
    bridge = _DelayedVaBridge(_DELAY_S)
    host = _VaMappingHost()
    host._bridge = bridge
    hex_widget = _FakeHexWidget(cursor_offset=0x500)
    host._hex_widget = hex_widget

    start = time.monotonic()
    host._on_cursor_offset_to_va()
    elapsed = time.monotonic() - start

    assert elapsed < _RETURN_BUDGET_S, (
        f"_on_cursor_offset_to_va blocked the calling thread for {elapsed:.3f}s waiting on a "
        f"{_DELAY_S}s file_offset_to_va RPC instead of dispatching it to a background worker"
    )
    assert host._va_status_label is not None
    assert not host._va_status_label.text(), (
        "the status label was already updated before _on_cursor_offset_to_va returned; "
        "file_offset_to_va is being awaited synchronously on the calling thread"
    )

    expected_va = 0x500 + _VA_BASE
    completed = _pump_until(qapp, lambda: bool(host._va_status_label.text()), timeout_s=_DELAY_S + 5.0)
    assert completed, "the status label was never updated after the delayed file_offset_to_va resolved"
    assert host._va_status_label.text() == f"file offset 0x500 -> VA 0x{expected_va:X}"


def test_m12_on_goto_va_failure_surfaced_asynchronously_not_inline(
    qapp: QApplication,
    dialog_recorder: _DialogRecorder,
) -> None:
    """A failing ``va_to_file_offset`` must warn only after the delayed RPC actually fails.

    Pre-fix, the blocking dispatch's ``try/except`` around
    ``run_bridge_coroutine(...)`` meant ``show_warning`` was already invoked,
    on the calling thread, by the time ``_on_goto_va`` returned -- after
    blocking for the full artificial delay. Post-fix,
    ``run_bridge_coroutine_logged`` delivers the exception via the queued
    ``call_error`` signal to ``_on_va_conversion_error``, so the handler
    returns immediately and no warning has been recorded until the Qt event
    loop is pumped and the background coroutine has had time to fail.

    Args:
        qapp: The shared offscreen QApplication fixture.
        dialog_recorder: Intercepts ``show_warning``/``show_info`` so no
            real modal dialog is spawned; the recorded warning is asserted
            directly.
    """
    bridge = _FailingVaBridge(_DELAY_S)
    host = _VaMappingHost()
    host._bridge = bridge
    host._hex_widget = _FakeHexWidget()
    assert host._va_goto_edit is not None
    host._va_goto_edit.setText("3000")

    start = time.monotonic()
    host._on_goto_va()
    elapsed = time.monotonic() - start

    assert elapsed < _RETURN_BUDGET_S, (
        f"_on_goto_va blocked the calling thread for {elapsed:.3f}s waiting for the {_DELAY_S}s "
        "failing va_to_file_offset RPC instead of dispatching it asynchronously"
    )
    assert not dialog_recorder.warning_calls, (
        "show_warning was already invoked before _on_goto_va returned; the failure is being "
        "handled synchronously by a blocking run_bridge_coroutine() call instead of the async "
        "on_error callback"
    )

    completed = _pump_until(qapp, lambda: bool(dialog_recorder.warning_calls), timeout_s=_DELAY_S + 5.0)
    assert completed, "the va_to_file_offset failure was never surfaced to the user"
    title, message = dialog_recorder.warning_calls[0]
    assert title == "VA Mapping"
    assert "Conversion failed" in message


def test_m13_on_open_performance_settings_returns_before_get_memory_usage_completes(
    qapp: QApplication,
    dialog_recorder: _DialogRecorder,
    stub_dialog_class: type[_StubLargeFileSettingsDialog],
) -> None:
    """``_on_open_performance_settings`` must return before the delayed ``get_memory_usage`` RPC finishes.

    Pre-fix, the handler called the blocking
    ``run_bridge_coroutine(bridge.get_memory_usage())`` directly, so it
    would not return -- and the settings dialog would not even be
    constructed -- until the full artificial delay had elapsed. Post-fix,
    the RPC is dispatched via ``run_bridge_coroutine_logged`` onto a
    background ``BridgeCallWorker`` thread, so the handler returns in a
    small fraction of the delay and the dialog is only constructed once the
    Qt event loop delivers the queued result.

    Args:
        qapp: The shared offscreen QApplication fixture.
        dialog_recorder: Intercepts ``show_warning``/``show_info`` so no
            real modal dialog is spawned; not expected to fire here.
        stub_dialog_class: Non-modal stand-in installed in place of
            ``LargeFileSettingsDialog``.
    """
    del dialog_recorder
    bridge = _DelayedVaBridge(_DELAY_S)
    host = _VaMappingHost()
    host._bridge = bridge

    start = time.monotonic()
    host._on_open_performance_settings()
    elapsed = time.monotonic() - start

    assert elapsed < _RETURN_BUDGET_S, (
        f"_on_open_performance_settings blocked the calling thread for {elapsed:.3f}s waiting on a "
        f"{_DELAY_S}s get_memory_usage RPC instead of dispatching it to a background worker"
    )
    assert not stub_dialog_class.instances, (
        "LargeFileSettingsDialog was already constructed before _on_open_performance_settings "
        "returned; get_memory_usage() is being awaited synchronously instead of dispatched via "
        "run_bridge_coroutine_logged"
    )

    completed = _pump_until(qapp, lambda: bool(stub_dialog_class.instances), timeout_s=_DELAY_S + 5.0)
    assert completed, "the performance-settings dialog was never presented after get_memory_usage resolved"
    presented = stub_dialog_class.instances[0]
    assert presented.current_chunk_kb == _CHUNK_BYTES // 1024
    assert presented.current_budget_mb == _BUDGET_BYTES // (1024 * 1024)


def test_m13_apply_chain_dispatches_chunk_then_budget_without_blocking(
    qapp: QApplication,
    dialog_recorder: _DialogRecorder,
    stub_dialog_class: type[_StubLargeFileSettingsDialog],
) -> None:
    """Applying settings must dispatch ``set_chunk_size``/``set_memory_budget`` as async round trips.

    Pre-fix, after the dialog was accepted, ``_on_open_performance_settings``
    issued two blocking ``run_bridge_coroutine`` calls back-to-back inside a
    single synchronous call frame, so both ``set_chunk_size`` and
    ``set_memory_budget`` -- and the resulting success dialog -- would
    already have happened by the time the enclosing call returned. Post-fix,
    each RPC is dispatched via ``run_bridge_coroutine_logged``, with
    ``set_memory_budget`` only dispatched from ``_on_chunk_size_applied``
    once ``set_chunk_size``'s own queued result signal has fired, so neither
    value is applied -- and no success dialog is shown -- until the Qt event
    loop is pumped.

    Args:
        qapp: The shared offscreen QApplication fixture.
        dialog_recorder: Intercepts ``show_warning``/``show_info`` so no
            real modal dialog is spawned; the final ``show_info`` call is
            asserted directly.
        stub_dialog_class: Non-modal stand-in installed in place of
            ``LargeFileSettingsDialog``; accepts immediately with fixed
            chunk/budget selections.
    """
    del stub_dialog_class
    bridge = _DelayedVaBridge(_DELAY_S)
    host = _VaMappingHost()
    host._bridge = bridge

    start = time.monotonic()
    host._on_open_performance_settings()
    elapsed = time.monotonic() - start

    assert elapsed < _RETURN_BUDGET_S, (
        f"_on_open_performance_settings blocked the calling thread for {elapsed:.3f}s across the "
        "get_memory_usage/set_chunk_size/set_memory_budget round trips instead of dispatching them "
        "asynchronously"
    )
    assert bridge.applied_chunk_bytes is None, (
        "set_chunk_size was already applied before _on_open_performance_settings returned; the "
        "apply chain is running synchronously on the calling thread"
    )
    assert bridge.applied_budget_bytes is None, (
        "set_memory_budget was already applied before _on_open_performance_settings returned; the "
        "apply chain is running synchronously on the calling thread"
    )
    assert not dialog_recorder.info_calls

    completed = _pump_until(qapp, lambda: bool(dialog_recorder.info_calls), timeout_s=3 * _DELAY_S + 8.0)
    assert completed, "the chunk-size/memory-budget apply chain never completed"

    assert bridge.applied_chunk_bytes == _SELECTED_CHUNK_KB * 1024
    assert bridge.applied_budget_bytes == _SELECTED_BUDGET_MB * 1024 * 1024
    title, message = dialog_recorder.info_calls[0]
    assert title == "Performance Settings"
    assert f"{_SELECTED_CHUNK_KB} KB" in message
    assert f"{_SELECTED_BUDGET_MB} MB" in message
