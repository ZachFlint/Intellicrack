# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D14 at the panel layer: Restart is one bridge operation.

``SandboxPanel`` used to synthesise a restart by chaining ``bridge.destroy``
and ``bridge.create`` across four callbacks, so the semantics of a failure
between the two phases lived in the GUI. The panel now issues a single
``SandboxBridge.restart`` call and lets the manager own the teardown/recreate
pair.

The ``qemu_config`` assertion is the S17-D06 regression guard at the panel
layer: a restart that dropped it would rebuild a QEMU sandbox with no disk
image.
"""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.qemu import QEMUConfig
from intellicrack.ui.panels import sandbox_panel as sandbox_panel_mod
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _RecordingBridge:
    """Bridge stand-in that records the restart/destroy/create calls it receives.

    Only the transport is stood in; the panel logic under test - which bridge
    operation it selects and which arguments it threads into it - runs for real.
    """

    def __init__(self) -> None:
        """Initialise empty call records."""
        self.restart_calls: list[tuple[str, dict[str, object]]] = []
        self.destroy_calls: list[str] = []
        self.create_calls: list[dict[str, object]] = []

    async def restart(self, instance_id: str, **kwargs: object) -> dict[str, object]:
        """Record a restart request.

        Args:
            instance_id: Instance the panel asked to restart.
            **kwargs: Configuration the panel threaded into the call.

        Returns:
            dict[str, object]: A replacement-instance result payload.
        """
        self.restart_calls.append((instance_id, dict(kwargs)))
        return {"instance_id": "sbx-new", "previous_instance_id": instance_id}

    async def destroy(self, instance_id: str) -> dict[str, object]:
        """Record a destroy request.

        Args:
            instance_id: Instance the panel asked to destroy.

        Returns:
            dict[str, object]: A success payload.
        """
        self.destroy_calls.append(instance_id)
        return {"success": True}

    async def create(self, **kwargs: object) -> dict[str, object]:
        """Record a create request.

        Args:
            **kwargs: Creation configuration the panel supplied.

        Returns:
            dict[str, object]: A new-instance payload.
        """
        self.create_calls.append(dict(kwargs))
        return {"instance_id": "sbx-created"}


def _dispatch_immediately(
    coro: Coroutine[object, object, object],
    on_success: Callable[[object], None] | None,
    on_error: Callable[[object], None] | None,
    parent: object,
    **_kwargs: object,
) -> None:
    """Drive a dispatched bridge coroutine to completion on the calling thread.

    Args:
        coro: Bridge coroutine the panel dispatched.
        on_success: Success callback invoked with the coroutine result.
        on_error: Failure callback (unused: the recording bridge never raises).
        parent: Qt parent (unused).
        **_kwargs: Structured logging context (ignored).
    """
    del on_error, parent
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(coro)
    finally:
        loop.close()
    if on_success is not None:
        on_success(result)


def _install_immediate_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the panel's async dispatch run its coroutine synchronously.

    Args:
        monkeypatch: Fixture used to replace the module-level dispatcher.
    """
    monkeypatch.setattr(sandbox_panel_mod, "run_bridge_coroutine_logged", _dispatch_immediately)


def _swallow_dialog(
    parent: object,
    title: str,
    message: str,
    *,
    exc: BaseException | None = None,
) -> None:
    """Stand in for ``show_error`` so no blocking modal opens during a test.

    Only used by tests asserting post-failure panel *state*; the dialog itself
    has its own dedicated gate in ``test_sandbox_panel_error_dialogs_s17d09``.

    Args:
        parent: Dialog parent widget (ignored).
        title: Dialog title (ignored).
        message: Dialog body (ignored).
        exc: Exception that triggered the dialog (ignored).
    """
    del parent, title, message, exc


@pytest.mark.usefixtures("qapp")
def test_restart_issues_a_single_bridge_restart_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restart must call ``bridge.restart`` once and never chain destroy+create.

    Args:
        monkeypatch: Fixture used to intercept the panel's async dispatch.
    """
    _install_immediate_dispatch(monkeypatch)
    panel = SandboxPanel()
    bridge = _RecordingBridge()
    panel._bridge = bridge
    panel.sandbox_id = "sbx-old"

    panel._on_restart()

    assert len(bridge.restart_calls) == 1, f"expected exactly one restart call, got {bridge.restart_calls!r}"
    assert bridge.destroy_calls == [], "the panel must not synthesise a restart from destroy+create"
    assert bridge.create_calls == []
    assert bridge.restart_calls[0][0] == "sbx-old"
    assert panel.sandbox_id == "sbx-new", "the panel must adopt the replacement instance id"
    assert "[+] Sandbox restarted" in panel._console_output.toPlainText()


@pytest.mark.usefixtures("qapp")
def test_restart_threads_the_toolbar_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restart must pass the toolbar timeout/network/memory values through.

    Args:
        monkeypatch: Fixture used to intercept the panel's async dispatch.
    """
    _install_immediate_dispatch(monkeypatch)
    panel = SandboxPanel()
    bridge = _RecordingBridge()
    panel._bridge = bridge
    panel.sandbox_id = "sbx-old"
    panel._timeout_spin.setValue(4242)
    panel._memory_limit_spin.setValue(3072)
    panel._network_enabled_check.setChecked(True)

    panel._on_restart()

    _, kwargs = bridge.restart_calls[0]
    assert kwargs["timeout_seconds"] == 4242
    assert kwargs["memory_limit_mb"] == 3072
    assert kwargs["network_enabled"] is True


@pytest.mark.usefixtures("qapp")
def test_restart_forwards_the_qemu_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """A QEMU restart must carry the persisted QEMU configuration (S17-D06).

    Args:
        monkeypatch: Fixture used to intercept the panel's async dispatch and
            to supply a known persisted QEMU configuration.
    """
    _install_immediate_dispatch(monkeypatch)
    loaded = QEMUConfig()
    monkeypatch.setattr(sandbox_panel_mod, "load_qemu_config", lambda: loaded)

    panel = SandboxPanel()
    bridge = _RecordingBridge()
    panel._bridge = bridge
    panel.sandbox_id = "sbx-old"
    panel.sandbox_type_combo.setCurrentText("QEMU")

    panel._on_restart()

    _, kwargs = bridge.restart_calls[0]
    assert kwargs["qemu_config"] is loaded, f"a QEMU restart must forward the persisted QEMU configuration; got {kwargs!r}"


@pytest.mark.usefixtures("qapp")
def test_failed_restart_clears_the_stale_instance_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed restart must not leave the panel pointing at a torn-down instance.

    Args:
        monkeypatch: Fixture used to fail the dispatched restart synchronously.
    """

    def _immediate_failure(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None,
        on_error: Callable[[object], None] | None,
        parent: object,
        **_kwargs: object,
    ) -> None:
        """Close the restart coroutine and report a failure.

        Args:
            coro: Bridge coroutine the panel dispatched.
            on_success: Success callback (unused).
            on_error: Failure callback invoked with a real error.
            parent: Qt parent (unused).
            **_kwargs: Structured logging context (ignored).
        """
        del on_success, parent
        coro.close()
        if on_error is not None:
            on_error(RuntimeError("Failed to restart sandbox: qemu image missing"))

    monkeypatch.setattr(sandbox_panel_mod, "run_bridge_coroutine_logged", _immediate_failure)
    monkeypatch.setattr(sandbox_panel_mod, "show_error", _swallow_dialog)

    panel = SandboxPanel()
    panel._bridge = _RecordingBridge()
    panel.sandbox_id = "sbx-old"
    panel._set_sandbox_controls_active(active=True)
    panel._status_poll_timer.start(5000)
    closed: list[bool] = []
    panel.tool_closed.connect(lambda: closed.append(True))

    try:
        panel._on_restart()
    finally:
        panel._status_poll_timer.stop()

    assert panel.sandbox_id is None, "a failed restart must clear the id of the torn-down instance"
    assert panel._status_indicator.text() == "Inactive"
    assert not panel.destroy_btn.isEnabled()
    assert not panel._status_poll_timer.isActive()
    assert closed == [True], "tool_closed must be emitted once no instance remains"
