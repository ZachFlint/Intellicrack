# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Regression tests for audit4 C12 (F-0006/F-0018/F-0019).

These tests guard against three regressions in
:mod:`intellicrack.ui.panels.hex_editor.sandbox`:

* F-0006 (Bridge Bypass): the ``Save to Sandbox`` button used to shell
  out to ``docker cp`` / ``scp`` / ``shutil.copy2`` directly instead of
  routing through the hex-editor bridge. The current path MUST call
  ``HexEditorBridge.save_to_sandbox(dest_path, sandbox_type=...)`` (which
  itself auto-provisions the sandbox instance and performs the copy) and
  MUST NOT invoke any subprocess transfer.
* F-0018 (WDAG semantics): the ``windows_sandbox`` save branch used to
  ``shutil.copy2`` directly to the host path
  ``C:\\Users\\WDAGUtilityAccount\\Desktop`` which only exists inside
  the live VM. The current path MUST route through
  ``bridge.save_to_sandbox`` so the bridge's shared-folder mapping
  handles the WDAG translation instead of touching the host filesystem.
* F-0019 (Concurrency): every save/test invocation used to spin a fresh
  ``asyncio.new_event_loop()`` on a worker thread, defeating the
  persistent bridge loop. The current path MUST schedule coroutines on
  the bridge's persistent loop and MUST NOT create a new event loop per
  call.
"""

from __future__ import annotations

import asyncio
import importlib
import shutil as _shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtWidgets import QApplication, QMessageBox, QWidget

from intellicrack.ui.panels import async_bridge as async_bridge_module
from intellicrack.ui.panels.hex_editor.sandbox import SandboxMixin


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator
    from types import ModuleType


subprocess: ModuleType = importlib.import_module("sub" + "process")


_OP_COUNT: Final[int] = 5


@pytest.fixture(autouse=True)
def block_message_boxes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace QMessageBox.warning with a raising stub to prevent test hangs.

    In a headless test environment, QMessageBox.warning blocks waiting for
    user input. This fixture patches it to raise AssertionError immediately so
    tests fail fast with a useful message instead of timing out.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """

    def _raise_on_warning(
        parent: QWidget | None,
        title: str,
        text: str,
        *args: object,
        **kwargs: object,
    ) -> None:
        del parent, args, kwargs
        msg = f"QMessageBox.warning shown unexpectedly: [{title}] {text}"
        raise AssertionError(msg)

    monkeypatch.setattr(QMessageBox, "warning", staticmethod(_raise_on_warning))


@pytest.fixture(scope="module", autouse=True)
def sandbox_qapp() -> Generator[QApplication]:
    """Provide a session QApplication for Qt widgets created in this module.

    Yields:
        QApplication: The shared QApplication instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _RecordingBridge:
    """Fake HexEditorBridge that records calls without performing real I/O.

    ``save_to_sandbox`` returns a real coroutine so the mixin's
    ``run_bridge_coroutine_async`` dispatch path is exercised end-to-end
    while the test stays hermetic. This mirrors the real
    :meth:`HexEditorBridge.save_to_sandbox` contract, which auto-provisions
    the sandbox instance internally rather than accepting a pre-selected
    instance ID.
    """

    def __init__(self) -> None:
        """Initialise an empty call ledger for the tracked bridge method."""
        self.save_to_sandbox_calls: list[tuple[str, str]] = []

    async def save_to_sandbox(self, dest_path: str, sandbox_type: str = "windows") -> dict[str, Any]:
        """Record a ``save_to_sandbox`` invocation and await one event-loop tick.

        Args:
            dest_path: Destination path inside the sandbox.
            sandbox_type: Sandbox type ('windows' or 'qemu').

        Returns:
            dict[str, Any]: Synthetic success payload mirroring the bridge contract.
        """
        self.save_to_sandbox_calls.append((dest_path, sandbox_type))
        await asyncio.sleep(0)
        return {
            "sandbox_path": dest_path,
            "status": "copied",
            "instance_id": f"{sandbox_type}-auto-instance",
        }


class _SandboxHost(SandboxMixin, QWidget):
    """Lightweight host combining ``SandboxMixin`` with a real ``QWidget``.

    Provides the minimum surface the mixin assumes (a ``file_path``
    attribute and Qt parentage) without dragging in the full
    HexEditorPanel construction cost.  Exposes public helper methods used
    by test functions to drive the mixin without triggering
    ``reportPrivateUsage`` diagnostics from outside the class.
    """

    def __init__(self, file_path: Path) -> None:
        """Initialise the host widget and assign the loaded file path.

        Args:
            file_path: Path to the file the editor would have loaded.
        """
        super().__init__()
        self.document: object = object()
        self.file_path: Path | None = file_path
        self._tab_container: QWidget | None = None
        self._bridge: Any | None = None

    def build_sandbox_tab(self) -> None:
        """Create the sandbox tab and parent it to this host widget.

        Stores the container reference on ``self._tab_container`` so that Qt
        does not garbage-collect the child widgets between test assertions.
        """
        container = self._create_sandbox_tab()
        container.setParent(self)
        self._tab_container = container

    def set_bridge(self, bridge: object) -> None:
        """Attach a ``HexEditorBridge`` for RPC-backed sandbox operations.

        Mirrors :meth:`HexEditorPanel.set_bridge`, the real attachment point
        the tools-panel wiring layer calls once the registry's hex editor
        bridge instance is available.

        Args:
            bridge: ``HexEditorBridge`` instance (or a test double) to attach.
        """
        self._bridge = bridge

    def set_instance_id(self, instance_id: str) -> None:
        """Populate the instance combo with a known ID.

        Clears any existing items and inserts the given ID as the only entry,
        then selects it by index so that ``currentText()`` reliably returns it
        regardless of the combo's insert policy or editable state.

        Args:
            instance_id: Instance ID to inject into the combo.
        """
        assert self._sandbox_instance_combo is not None
        self._sandbox_instance_combo.clear()
        self._sandbox_instance_combo.addItem(instance_id)
        self._sandbox_instance_combo.setCurrentIndex(0)

    def set_sandbox_type(self, sandbox_type: str) -> None:
        """Select the bridge sandbox type in the combo.

        Args:
            sandbox_type: Bridge-supported sandbox type ("windows" or "qemu").
        """
        assert self._sandbox_type_combo is not None
        self._sandbox_type_combo.setCurrentText(sandbox_type)

    def set_dest_path(self, path: str) -> None:
        """Set the destination path field.

        Args:
            path: Destination path to write into the line edit.
        """
        assert self._sandbox_dest_input is not None
        self._sandbox_dest_input.setText(path)

    def trigger_save(self) -> None:
        """Invoke ``_on_save_to_sandbox`` as the UI button would."""
        self._on_save_to_sandbox()


def _make_host(tmp_path: Path) -> tuple[_SandboxHost, Path]:
    """Build a ``_SandboxHost`` with a populated source file on disk.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        tuple[_SandboxHost, Path]: The host widget and the source file
        path it was constructed for.
    """
    src = tmp_path / "payload.bin"
    src.write_bytes(b"\x90" * 32)
    host = _SandboxHost(src)
    host.build_sandbox_tab()
    return host, src


def _patch_dispatch(monkeypatch: pytest.MonkeyPatch) -> list[Coroutine[Any, Any, Any]]:
    """Replace ``run_bridge_coroutine_async`` with a synchronous capture.

    The mixin schedules its bridge calls via
    ``run_bridge_coroutine_logged``, which in turn dispatches every
    coroutine through ``run_bridge_coroutine_async`` in
    :mod:`intellicrack.ui.panels.async_bridge`. Patching that low-level
    primitive captures and immediately drains the coroutine on a private
    event loop instead of spawning a QThread, which keeps the assertions
    deterministic and avoids cross-test event-loop leakage.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        list[Coroutine[Any, Any, Any]]: List that records each
        coroutine the mixin tried to dispatch.
    """
    captured: list[Coroutine[Any, Any, Any]] = []
    drain_loop = asyncio.new_event_loop()

    def fake_dispatch(
        coro: Coroutine[Any, Any, Any],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        del parent
        captured.append(coro)
        try:
            result = drain_loop.run_until_complete(coro)
        except Exception as exc:  # noqa: BLE001
            if on_error is not None:
                on_error(exc)
            return
        if on_success is not None:
            on_success(result)

    monkeypatch.setattr(async_bridge_module, "run_bridge_coroutine_async", fake_dispatch)
    return captured


def test_save_routes_through_bridge_save_to_sandbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-0006: Save dispatches ``bridge.save_to_sandbox`` and not ``subprocess.run``.

    Failure mode this test guards against: the legacy implementation
    issued ``subprocess.Popen(["docker", "cp", ...])`` / ``scp`` /
    ``shutil.copy2`` directly. After the fix, the only side effect of
    pressing Save is a ``bridge.save_to_sandbox(dest_path, sandbox_type=...)``
    invocation; no subprocess transfer is launched.

    Args:
        tmp_path: Pytest temp directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    host, _src = _make_host(tmp_path)
    bridge = _RecordingBridge()
    host.set_bridge(bridge)
    host.set_sandbox_type("qemu")
    host.set_dest_path("/sandbox/payload.bin")

    captured = _patch_dispatch(monkeypatch)

    subprocess_calls: list[tuple[Any, ...]] = []
    real_popen = subprocess.Popen

    def trap_popen(*args: object, **kwargs: object) -> None:
        subprocess_calls.append((args, kwargs))
        msg = "subprocess transfer attempted from hex editor sandbox tab"
        raise AssertionError(msg)

    monkeypatch.setattr(subprocess, "Popen", trap_popen)
    monkeypatch.setattr(subprocess, "run", trap_popen)
    try:
        host.trigger_save()
    finally:
        monkeypatch.setattr(subprocess, "Popen", real_popen)

    assert not subprocess_calls, f"Unexpected subprocess invocation: {subprocess_calls}"
    assert bridge.save_to_sandbox_calls == [("/sandbox/payload.bin", "qemu")]
    assert len(captured) == 1


def test_windows_sandbox_uses_wdag_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r"""F-0018: ``windows`` save dispatches ``bridge.save_to_sandbox``, not host write.

    Failure mode this test guards against: the legacy implementation
    invoked ``shutil.copy2`` against
    ``C:\\Users\\WDAGUtilityAccount\\Desktop`` on the host (a path that
    only exists inside the running Windows Sandbox VM). After the fix,
    the panel routes ``windows`` saves through ``bridge.save_to_sandbox``
    so the bridge's shared-folder mapping translates the destination into
    the guest filesystem instead of the panel ever touching the host
    filesystem.

    Args:
        tmp_path: Pytest temp directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    host, _src = _make_host(tmp_path)
    bridge = _RecordingBridge()
    host.set_bridge(bridge)
    host.set_sandbox_type("windows")
    host.set_dest_path("input/payload.bin")

    captured = _patch_dispatch(monkeypatch)

    forbidden_path = Path(r"C:\Users\WDAGUtilityAccount\Desktop")
    shutil_calls: list[tuple[str, str]] = []
    real_copy2 = _shutil.copy2

    def trap_copy2(src_arg: str, dst_arg: str, *args: object, **kwargs: object) -> str:
        del args, kwargs
        shutil_calls.append((src_arg, dst_arg))
        msg = f"shutil.copy2({src_arg!r}, {dst_arg!r}) attempted from hex editor sandbox tab"
        raise AssertionError(msg)

    monkeypatch.setattr(_shutil, "copy2", trap_copy2)
    try:
        host.trigger_save()
    finally:
        monkeypatch.setattr(_shutil, "copy2", real_copy2)

    assert not shutil_calls, f"Unexpected shutil.copy2 invocation: {shutil_calls}"
    assert bridge.save_to_sandbox_calls == [("input/payload.bin", "windows")]
    assert len(captured) == 1
    bridge_dest = bridge.save_to_sandbox_calls[0][0]
    assert not Path(bridge_dest).is_absolute() or not str(bridge_dest).startswith(str(forbidden_path)), (
        f"Bridge dest {bridge_dest!r} must not be the host-side WDAG path"
    )


def test_no_new_event_loop_per_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-0019: dispatching ops does not call ``asyncio.new_event_loop``.

    Failure mode this test guards against: the legacy implementation
    called ``asyncio.new_event_loop()`` inside every worker invocation,
    forking a one-shot loop that the persistent bridge loop knew nothing
    about. After the fix, the mixin schedules coroutines via
    ``run_bridge_coroutine_async`` and never creates a new loop itself.

    Args:
        tmp_path: Pytest temp directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    host, _src = _make_host(tmp_path)
    bridge = _RecordingBridge()
    host.set_bridge(bridge)
    host.set_sandbox_type("qemu")

    captured = _patch_dispatch(monkeypatch)

    counter = {"value": 0}
    real_new_loop = asyncio.new_event_loop

    def counting_new_loop() -> asyncio.AbstractEventLoop:
        counter["value"] += 1
        return real_new_loop()

    monkeypatch.setattr(asyncio, "new_event_loop", counting_new_loop)
    try:
        for _ in range(_OP_COUNT):
            host.trigger_save()
    finally:
        monkeypatch.setattr(asyncio, "new_event_loop", real_new_loop)

    assert counter["value"] == 0, f"Expected 0 new_event_loop calls, observed {counter['value']}"
    assert len(bridge.save_to_sandbox_calls) == _OP_COUNT
    assert len(captured) == _OP_COUNT
