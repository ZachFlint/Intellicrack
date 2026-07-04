# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for GUI audit finding M7 in ``hex_editor/patches.py``.

M7 -- ``_on_export_patches`` and ``_on_import_patches`` previously called the
**blocking** ``run_bridge_coroutine(bridge.export_patches(...))`` /
``run_bridge_coroutine(bridge.import_patches(...))`` directly from a
synchronous Qt button-click slot. For BPS/UPS formats (and, in general, for
any non-trivial patch payload) the bridge performs a full byte-diff or
target-rebuild against the original file on disk; with the blocking variant
that work runs while the Qt GUI thread sits parked in ``future.result()``
with no ``processEvents``/event-loop pumping, freezing the whole application
window for the duration of the export/import.

The fix routes both handlers through ``run_bridge_coroutine_logged`` (built
on ``BridgeCallWorker`` / ``run_bridge_coroutine_async``), which starts the
bridge coroutine on the persistent background event-loop thread and returns
to the caller immediately; the file write (export) or patch-count/viewport
refresh (import) is completed later by ``_on_export_patches_success`` /
``_on_import_patches_success``, invoked back on the GUI thread once Qt
delivers the worker's queued ``call_finished``/``call_error`` signal.

Every test below drives the real ``PatchesMixin`` handlers against a real
``HexEditorBridge`` subclass bound to a real ``intellicrack_hexcore``
document. The subclass injects an artificial ``asyncio.sleep`` delay (or an
unconditional failure) into ``export_patches``/``import_patches`` so the
non-blocking dispatch contract can be measured directly: the handler must
return to its caller in a small fraction of the delay (proving it did not
wait on ``future.result()`` inline), the on-disk file / document contents
must remain untouched until the delayed coroutine actually completes on the
background thread and the Qt event loop is pumped, and the success/failure
callback that finally mutates state must be observed running on the GUI
thread.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QFileDialog, QTreeWidget, QTreeWidgetItem, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor import patches as patches_module
from intellicrack.ui.panels.hex_editor.patches import PatchesMixin


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real hex documents",
)


pytestmark = pytest.mark.usefixtures("qapp")


_DELAY_S: float = 0.4
"""Artificial async delay injected into the fake bridge RPCs, in seconds."""

_RETURN_BUDGET_S: float = _DELAY_S / 2
"""Maximum wall-clock time a non-blocking dispatch may take to return."""

_PUMP_TIMEOUT_S: float = _DELAY_S + 8.0
"""Ceiling for pumping the Qt event loop while waiting for the delayed callback."""

_DOC_LEN: int = 32
_PATCH_OFFSET: int = 0x10
_PATCH_BYTE: bytes = b"\x5a"


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


class _DelayedPatchBridge(HexEditorBridge):
    """``HexEditorBridge`` whose ``export_patches``/``import_patches`` impose an artificial delay.

    Lets a test distinguish a non-blocking dispatch (the caller returns well
    before the coroutine finishes) from a blocking one (the caller only
    returns once the coroutine, including the delay, has completed).
    """

    def __init__(self, delay_s: float) -> None:
        """Initialise the bridge with the configured artificial delay.

        Args:
            delay_s: Number of seconds ``export_patches``/``import_patches``
                sleep for before performing the real operation.
        """
        super().__init__()
        self._delay_s: float = delay_s

    async def export_patches(self, patch_format: str = "ips", original_path: str | None = None) -> str:
        """Sleep, then perform the real bridge patch export.

        Args:
            patch_format: Patch format identifier forwarded to the real export.
            original_path: Original source path forwarded to the real export.

        Returns:
            str: Base64-encoded patch data produced by the real export.
        """
        await asyncio.sleep(self._delay_s)
        return await super().export_patches(patch_format, original_path)

    async def import_patches(self, data_b64: str, original_path: str | None = None) -> int:
        """Sleep, then perform the real bridge patch import.

        Args:
            data_b64: Base64-encoded patch data forwarded to the real import.
            original_path: Original source path forwarded to the real import.

        Returns:
            int: Number of patch records applied by the real import.
        """
        await asyncio.sleep(self._delay_s)
        return await super().import_patches(data_b64, original_path)


class _FailingExportBridge(HexEditorBridge):
    """``HexEditorBridge`` whose ``export_patches`` raises after an artificial delay.

    Used to prove that a failed export RPC is surfaced through the async
    ``on_error`` callback path rather than by blocking the caller until the
    failure occurs.
    """

    def __init__(self, delay_s: float) -> None:
        """Initialise the bridge with the configured artificial delay.

        Args:
            delay_s: Number of seconds ``export_patches`` sleeps for before raising.
        """
        super().__init__()
        self._delay_s: float = delay_s

    async def export_patches(self, patch_format: str = "ips", original_path: str | None = None) -> str:
        """Sleep, then raise a simulated RPC failure.

        Args:
            patch_format: Ignored; failure is unconditional.
            original_path: Ignored; failure is unconditional.

        Returns:
            str: Never returns; always raises.

        Raises:
            RuntimeError: Always, after the artificial delay.
        """
        del patch_format, original_path
        await asyncio.sleep(self._delay_s)
        msg = "simulated export_patches failure"
        raise RuntimeError(msg)


class _FailingImportBridge(HexEditorBridge):
    """``HexEditorBridge`` whose ``import_patches`` raises after an artificial delay.

    Used to prove that a failed import RPC is surfaced through the async
    ``on_error`` callback path rather than by blocking the caller until the
    failure occurs.
    """

    def __init__(self, delay_s: float) -> None:
        """Initialise the bridge with the configured artificial delay.

        Args:
            delay_s: Number of seconds ``import_patches`` sleeps for before raising.
        """
        super().__init__()
        self._delay_s: float = delay_s

    async def import_patches(self, data_b64: str, original_path: str | None = None) -> int:
        """Sleep, then raise a simulated RPC failure.

        Args:
            data_b64: Ignored; failure is unconditional.
            original_path: Ignored; failure is unconditional.

        Returns:
            int: Never returns; always raises.

        Raises:
            RuntimeError: Always, after the artificial delay.
        """
        del data_b64, original_path
        await asyncio.sleep(self._delay_s)
        msg = "simulated import_patches failure"
        raise RuntimeError(msg)


class _DialogRecorder:
    """Records ``show_info``/``show_warning`` invocations and the calling thread.

    Standing in for the real modal-dialog helpers so tests never spawn a
    real ``QMessageBox`` (which would block on user interaction), while
    still observing exactly when and from which OS thread each call was
    made.
    """

    def __init__(self) -> None:
        """Initialise empty call ledgers."""
        self.calls: list[tuple[str, str]] = []
        self.thread_idents: list[int] = []

    def __call__(self, _parent: QWidget | None, title: str, message: str) -> None:
        """Record the call's title, message, and calling thread identity.

        Args:
            _parent: Parent widget for the dialog (unused; not shown).
            title: Dialog title.
            message: Dialog message body.
        """
        self.calls.append((title, message))
        self.thread_idents.append(threading.get_ident())


class _PatchesHarness(QWidget, PatchesMixin):
    """Minimal real ``PatchesMixin`` consumer used to drive the GUI slots.

    Overrides the main-thread success/error callbacks to additionally
    record the identity of the thread that executed them, so tests can
    assert those callbacks ran on the GUI thread rather than on the
    background bridge event-loop thread that produced the result.
    """

    def __init__(self, document: object, bridge: HexEditorBridge, file_path: Path | None = None) -> None:
        """Wire the mixin's required attribute slots to a real document and bridge.

        Args:
            document: Real ``intellicrack_hexcore`` document the mixin operates on.
            bridge: Hex editor bridge (real or delay/failure-injecting subclass) to attach.
            file_path: Optional on-disk source path (required for BPS/UPS branches).
        """
        QWidget.__init__(self)
        self.document = document
        self._document = document
        self._hex_widget = None
        self._patches_tree = QTreeWidget()
        self._patches_tree.setColumnCount(3)
        self._original_data_cache = {}
        self._bridge = bridge
        self.file_path = file_path
        self._pending_export_patches_path = None
        self._pending_export_patches_count = 0
        self._pending_export_patches_format = None
        self._pending_import_patches_path = None
        self._pending_import_patches_suffix = None
        self.main_thread_calls: dict[str, int] = {}

    def add_patch_marker(self) -> None:
        """Add a single tree entry so the export handler sees a non-zero patch count."""
        self._patches_tree.addTopLevelItem(QTreeWidgetItem([f"0x{_PATCH_OFFSET:08X}", "0x00", "0x5A"]))

    def export_patches(self) -> None:
        """Invoke the mixin's export slot as a public test entry point."""
        self._on_export_patches()

    def import_patches(self) -> None:
        """Invoke the mixin's import slot as a public test entry point."""
        self._on_import_patches()

    @property
    def pending_export_path(self) -> str | None:
        """The mixin's recorded pending-export destination path.

        Returns:
            str | None: The destination path captured for the in-flight export
                dispatch, or ``None`` once the async callback has cleared it.
        """
        return self._pending_export_patches_path

    @property
    def pending_export_format(self) -> str | None:
        """The mixin's recorded pending-export patch format.

        Returns:
            str | None: The patch format captured for the in-flight export
                dispatch, or ``None`` once the async callback has cleared it.
        """
        return self._pending_export_patches_format

    def _on_export_patches_success(self, result: object) -> None:
        """Record the calling thread, then apply the mixin's default handling.

        Args:
            result: Base64-encoded patch bytes returned by the bridge.
        """
        self.main_thread_calls["export_success"] = threading.get_ident()
        super()._on_export_patches_success(result)

    def _on_export_patches_error(self, exc: object) -> None:
        """Record the calling thread, then apply the mixin's default handling.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        self.main_thread_calls["export_error"] = threading.get_ident()
        super()._on_export_patches_error(exc)

    def _on_import_patches_success(self, result: object) -> None:
        """Record the calling thread, then apply the mixin's default handling.

        Args:
            result: Number of patch records applied, returned by the bridge.
        """
        self.main_thread_calls["import_success"] = threading.get_ident()
        super()._on_import_patches_success(result)

    def _on_import_patches_error(self, exc: object) -> None:
        """Record the calling thread, then apply the mixin's default handling.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        self.main_thread_calls["import_error"] = threading.get_ident()
        super()._on_import_patches_error(exc)


def _make_real_ips_patch() -> bytes:
    """Produce a genuine IPS patch blob via the real hexcore backend.

    Returns:
        bytes: Raw (not base64-encoded) IPS patch bytes covering a single
            one-byte modification at ``_PATCH_OFFSET``.
    """
    prep = hexcore.HexDocument.open_bytes(bytes(_DOC_LEN))
    prep.write_bytes(_PATCH_OFFSET, _PATCH_BYTE)
    ips_bytes: bytes = prep.export_patches_ips()
    return ips_bytes


def test_m7_export_patches_returns_before_delayed_bridge_call_completes(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """M7: ``_on_export_patches`` must return before the delayed bridge RPC finishes.

    Pre-fix, ``_on_export_patches`` called the blocking
    ``run_bridge_coroutine(bridge.export_patches(...))``, which invokes
    ``future.result()`` on the calling (GUI) thread and would not return
    until the full artificial delay plus the real export had elapsed, with
    the destination file already written by the time the call returned.
    Post-fix, the RPC is dispatched via ``run_bridge_coroutine_logged`` onto
    a background ``BridgeCallWorker`` thread, so the handler returns in a
    small fraction of the delay and the file does not exist until the Qt
    event loop is later pumped and the queued result signal fires.

    Args:
        qapp: The shared QApplication fixture.
        monkeypatch: Pytest fixture used to stub the save dialog and the
            info/warning dialog helpers so no real modal is spawned.
        tmp_path: Pytest temporary directory fixture.
    """
    dialogs = _DialogRecorder()
    monkeypatch.setattr(patches_module, "show_info", dialogs)
    monkeypatch.setattr(patches_module, "show_warning", dialogs)

    save_path = tmp_path / "m7_export.ips"
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *_a, **_k: (str(save_path), "IPS Patches (*.ips)"),
    )

    document = hexcore.HexDocument.open_bytes(bytes(_DOC_LEN))
    document.write_bytes(_PATCH_OFFSET, _PATCH_BYTE)
    bridge = _DelayedPatchBridge(_DELAY_S)
    bridge.document = document
    harness = _PatchesHarness(document, bridge)
    harness.add_patch_marker()

    gui_thread = threading.get_ident()
    try:
        start = time.monotonic()
        harness.export_patches()
        elapsed = time.monotonic() - start

        assert elapsed < _RETURN_BUDGET_S, (
            f"_on_export_patches blocked the calling thread for {elapsed:.3f}s waiting on a "
            f"{_DELAY_S}s export_patches RPC instead of dispatching it to a background worker"
        )
        assert not save_path.exists(), (
            "the patch file already exists before _on_export_patches returned; the dispatch is "
            "blocking (awaiting the coroutine synchronously) instead of asynchronous"
        )

        completed = _pump_until(qapp, save_path.exists, timeout_s=_PUMP_TIMEOUT_S)
        assert completed, "the export never completed after pumping the Qt event loop"

        written = save_path.read_bytes()
        assert written.startswith(b"PATCH"), "the written file is not a valid IPS patch produced by the bridge"
        roundtrip = hexcore.HexDocument.open_bytes(bytes(_DOC_LEN))
        roundtrip.import_patches_ips(written)
        assert bytes(roundtrip.read(_PATCH_OFFSET, 1)) == _PATCH_BYTE, "exported patch does not reproduce the real modification"

        assert dialogs.calls
        assert dialogs.calls[-1] == ("Export Patches", "Exported 1 patch(es).")
        assert dialogs.thread_idents[-1] == gui_thread, "the completion dialog was not shown from the GUI thread"
        assert harness.main_thread_calls.get("export_success") == gui_thread, (
            "the success callback that writes the file did not run back on the GUI thread"
        )
    finally:
        harness.deleteLater()


def test_m7_export_patches_failure_surfaced_only_after_async_callback(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """M7: a failed export RPC is surfaced via the async error callback, not a blocking wait.

    Pre-fix, the blocking dispatch's ``try/except`` around
    ``run_bridge_coroutine(...)`` meant ``show_warning`` was already invoked,
    on the calling thread, by the time ``_on_export_patches`` returned --
    after blocking for the full delay. Post-fix, ``run_bridge_coroutine_logged``
    delivers the exception via the queued ``call_error`` signal to
    ``_on_export_patches_error``, so the handler returns immediately and no
    warning has been recorded until the Qt event loop is pumped and the
    background coroutine has had time to fail.

    Args:
        qapp: The shared QApplication fixture.
        monkeypatch: Pytest fixture used to stub the save dialog and the
            info/warning dialog helpers so no real modal is spawned.
        tmp_path: Pytest temporary directory fixture.
    """
    dialogs = _DialogRecorder()
    monkeypatch.setattr(patches_module, "show_info", dialogs)
    monkeypatch.setattr(patches_module, "show_warning", dialogs)

    save_path = tmp_path / "m7_export_fail.ips"
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *_a, **_k: (str(save_path), "IPS Patches (*.ips)"),
    )

    document = hexcore.HexDocument.open_bytes(bytes(_DOC_LEN))
    document.write_bytes(_PATCH_OFFSET, _PATCH_BYTE)
    bridge = _FailingExportBridge(_DELAY_S)
    bridge.document = document
    harness = _PatchesHarness(document, bridge)
    harness.add_patch_marker()

    gui_thread = threading.get_ident()
    try:
        start = time.monotonic()
        harness.export_patches()
        elapsed = time.monotonic() - start

        assert elapsed < _RETURN_BUDGET_S, (
            f"_on_export_patches blocked the calling thread for {elapsed:.3f}s waiting for the "
            f"{_DELAY_S}s failing export_patches RPC instead of dispatching it asynchronously"
        )
        assert not dialogs.calls, (
            "show_warning was already invoked before _on_export_patches returned; the failure is "
            "being handled synchronously on the calling thread instead of via the async callback"
        )

        completed = _pump_until(qapp, lambda: bool(dialogs.calls), timeout_s=_PUMP_TIMEOUT_S)
        assert completed, "the export failure was never surfaced to the user"

        title, message = dialogs.calls[0]
        assert title == "Export Patches"
        assert "Export failed" in message
        assert dialogs.thread_idents[-1] == gui_thread, (
            "the failure callback must be delivered on the GUI thread via the queued call_error "
            "signal, not invoked directly from the background bridge event-loop thread"
        )
        assert not save_path.exists(), "no file must be written when the export RPC fails"
        assert harness.main_thread_calls.get("export_error") == gui_thread
    finally:
        harness.deleteLater()


def test_m7_import_patches_returns_before_delayed_bridge_call_completes(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """M7: ``_on_import_patches`` must return before the delayed bridge RPC finishes.

    Pre-fix, ``_on_import_patches`` called the blocking
    ``run_bridge_coroutine(bridge.import_patches(...))`` directly on the GUI
    thread, so the document would already carry the applied patch by the
    time the call returned and the caller would have blocked for the full
    delay. Post-fix, the RPC is dispatched via ``run_bridge_coroutine_logged``,
    so the handler returns in a small fraction of the delay and the document
    is untouched until the Qt event loop is pumped and the queued result
    signal fires.

    Args:
        qapp: The shared QApplication fixture.
        monkeypatch: Pytest fixture used to stub the open dialog and the
            info/warning dialog helpers so no real modal is spawned.
        tmp_path: Pytest temporary directory fixture.
    """
    dialogs = _DialogRecorder()
    monkeypatch.setattr(patches_module, "show_info", dialogs)
    monkeypatch.setattr(patches_module, "show_warning", dialogs)

    ips_bytes = _make_real_ips_patch()
    source_path = tmp_path / "m7_import.ips"
    source_path.write_bytes(ips_bytes)
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *_a, **_k: (str(source_path), "Patch Files (*.ips *.ips32 *.bps *.ups)"),
    )

    document = hexcore.HexDocument.open_bytes(bytes(_DOC_LEN))
    bridge = _DelayedPatchBridge(_DELAY_S)
    bridge.document = document
    harness = _PatchesHarness(document, bridge)

    gui_thread = threading.get_ident()
    try:
        assert bytes(document.read(_PATCH_OFFSET, 1)) != _PATCH_BYTE, "test premise: document starts unpatched"

        start = time.monotonic()
        harness.import_patches()
        elapsed = time.monotonic() - start

        assert elapsed < _RETURN_BUDGET_S, (
            f"_on_import_patches blocked the calling thread for {elapsed:.3f}s waiting on a "
            f"{_DELAY_S}s import_patches RPC instead of dispatching it to a background worker"
        )
        assert bytes(document.read(_PATCH_OFFSET, 1)) != _PATCH_BYTE, (
            "the document was already mutated before _on_import_patches returned; the dispatch is "
            "blocking (awaiting the coroutine synchronously) instead of asynchronous"
        )

        completed = _pump_until(
            qapp,
            lambda: bool(dialogs.calls),
            timeout_s=_PUMP_TIMEOUT_S,
        )
        assert completed, "the import never completed after pumping the Qt event loop"

        assert bytes(document.read(_PATCH_OFFSET, 1)) == _PATCH_BYTE, (
            "the import did not apply the patch to the document"
        )
        assert dialogs.calls
        assert dialogs.calls[-1] == ("Import Patches", "Applied 1 patch record(s).")
        assert dialogs.thread_idents[-1] == gui_thread, "the completion dialog was not shown from the GUI thread"
        assert harness.main_thread_calls.get("import_success") == gui_thread, (
            "the success callback that applies the patch count did not run back on the GUI thread"
        )
    finally:
        harness.deleteLater()


def test_m7_import_patches_failure_surfaced_only_after_async_callback(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """M7: a failed import RPC is surfaced via the async error callback, not a blocking wait.

    Pre-fix, ``_on_import_patches`` called the blocking
    ``run_bridge_coroutine(bridge.import_patches(...))`` inside a
    ``try/except``, so ``show_warning`` would already have been invoked, on
    the calling thread, by the time the handler returned -- after blocking
    for the full delay. Post-fix, ``run_bridge_coroutine_logged`` delivers
    the exception via the queued ``call_error`` signal to
    ``_on_import_patches_error``, so the handler returns immediately and no
    warning has been recorded until the Qt event loop is pumped.

    Args:
        qapp: The shared QApplication fixture.
        monkeypatch: Pytest fixture used to stub the open dialog and the
            info/warning dialog helpers so no real modal is spawned.
        tmp_path: Pytest temporary directory fixture.
    """
    dialogs = _DialogRecorder()
    monkeypatch.setattr(patches_module, "show_info", dialogs)
    monkeypatch.setattr(patches_module, "show_warning", dialogs)

    ips_bytes = _make_real_ips_patch()
    source_path = tmp_path / "m7_import_fail.ips"
    source_path.write_bytes(ips_bytes)
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *_a, **_k: (str(source_path), "Patch Files (*.ips *.ips32 *.bps *.ups)"),
    )

    document = hexcore.HexDocument.open_bytes(bytes(_DOC_LEN))
    bridge = _FailingImportBridge(_DELAY_S)
    bridge.document = document
    harness = _PatchesHarness(document, bridge)

    gui_thread = threading.get_ident()
    try:
        start = time.monotonic()
        harness.import_patches()
        elapsed = time.monotonic() - start

        assert elapsed < _RETURN_BUDGET_S, (
            f"_on_import_patches blocked the calling thread for {elapsed:.3f}s waiting for the "
            f"{_DELAY_S}s failing import_patches RPC instead of dispatching it asynchronously"
        )
        assert not dialogs.calls, (
            "show_warning was already invoked before _on_import_patches returned; the failure is "
            "being handled synchronously on the calling thread instead of via the async callback"
        )

        completed = _pump_until(qapp, lambda: bool(dialogs.calls), timeout_s=_PUMP_TIMEOUT_S)
        assert completed, "the import failure was never surfaced to the user"

        title, message = dialogs.calls[0]
        assert title == "Import Patches"
        assert "Import failed" in message
        assert dialogs.thread_idents[-1] == gui_thread, (
            "the failure callback must be delivered on the GUI thread via the queued call_error "
            "signal, not invoked directly from the background bridge event-loop thread"
        )
        assert bytes(document.read(_PATCH_OFFSET, 1)) != _PATCH_BYTE, "no patch must be applied when the import RPC fails"
        assert harness.main_thread_calls.get("import_error") == gui_thread
    finally:
        harness.deleteLater()


def test_m7_export_patches_pending_state_cleared_after_success(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """M7: the harness's pending-export bookkeeping is cleared once the async callback runs.

    Proves the new ``_pending_export_patches_*`` attributes that the fix
    introduced to carry state across the async dispatch boundary are
    populated immediately (before the delayed RPC resolves) and reset back
    to ``None`` once ``_on_export_patches_success`` has run. Pre-fix there
    were no such attributes at all -- the save path, count, and format were
    plain locals captured in the (blocking) call frame -- so this state
    machine did not exist.

    Args:
        qapp: The shared QApplication fixture.
        monkeypatch: Pytest fixture used to stub the save dialog and the
            info/warning dialog helpers so no real modal is spawned.
        tmp_path: Pytest temporary directory fixture.
    """
    dialogs = _DialogRecorder()
    monkeypatch.setattr(patches_module, "show_info", dialogs)
    monkeypatch.setattr(patches_module, "show_warning", dialogs)

    save_path = tmp_path / "m7_export_pending.ips"
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *_a, **_k: (str(save_path), "IPS Patches (*.ips)"),
    )

    document = hexcore.HexDocument.open_bytes(bytes(_DOC_LEN))
    document.write_bytes(_PATCH_OFFSET, _PATCH_BYTE)
    bridge = _DelayedPatchBridge(_DELAY_S)
    bridge.document = document
    harness = _PatchesHarness(document, bridge)
    harness.add_patch_marker()

    try:
        harness.export_patches()

        assert harness.pending_export_path == str(save_path), "the pending export path was not recorded before the async dispatch"
        assert harness.pending_export_format == "ips", "the pending export format was not recorded"

        completed = _pump_until(qapp, save_path.exists, timeout_s=_PUMP_TIMEOUT_S)
        assert completed, "the export never completed after pumping the Qt event loop"

        assert harness.pending_export_path is None, "pending export path was not cleared after success"
        assert harness.pending_export_format is None, "pending export format was not cleared after success"
    finally:
        harness.deleteLater()
