# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D14 at the bridge layer: ``SandboxBridge.restart``.

The panel used to synthesise a restart from ``bridge.destroy`` followed by
``bridge.create``, so there was no restart operation any other caller (the AI
orchestrator, a headless workflow, a future panel) could reuse. These tests
drive the real :class:`SandboxBridge` against a real :class:`SandboxManager`
whose backend factory yields the real
:class:`~tests.sandbox.conftest.LocalProcessSandbox`, so the restart performs
genuine work: the original sandbox's real work directory is removed and the
replacement's real work directory exists.

The ``qemu_config`` forwarding assertion is the S17-D06 regression guard at the
bridge layer: a restart that dropped it would rebuild a QEMU sandbox with no
disk image.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.manager import SandboxManager
from intellicrack.sandbox.qemu import QEMUConfig
from tests.sandbox.conftest import LocalProcessSandbox


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.sandbox.base import SandboxBase
    from intellicrack.sandbox.manager import SandboxType


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Execute a coroutine on a dedicated event loop.

    Args:
        coro: Awaitable to run to completion.

    Returns:
        T: The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class _LocalBackendManager(SandboxManager):
    """Real manager whose backend factory yields real local-process sandboxes."""

    def __init__(self) -> None:
        """Initialise the manager and its build recorder."""
        super().__init__()
        self.builds: list[tuple[SandboxType, QEMUConfig | None, SandboxConfig]] = []

    def _build_sandbox(
        self,
        sandbox_type: SandboxType,
        config: SandboxConfig | None = None,
        qemu_config: QEMUConfig | None = None,
    ) -> SandboxBase:
        """Build a real local-process backend, recording the arguments received.

        Args:
            sandbox_type: Sandbox type requested by the manager.
            config: Generic configuration the manager forwarded.
            qemu_config: QEMU configuration the manager forwarded.

        Returns:
            SandboxBase: A real ``LocalProcessSandbox``.
        """
        effective = config or SandboxConfig()
        self.builds.append((sandbox_type, qemu_config, effective))
        return LocalProcessSandbox(effective)

    def registered_ids(self) -> set[str]:
        """Report the identifiers the manager currently tracks.

        Returns:
            set[str]: Registered instance identifiers.
        """
        return set(self._instances)


def _workdir(manager: _LocalBackendManager, instance_id: str) -> Path:
    """Read the real work directory backing a registered instance.

    Args:
        manager: Manager owning the instance.
        instance_id: Identifier of the instance to inspect.

    Returns:
        Path: The sandbox's real work directory.
    """
    match = next(inst for inst in manager.instances if inst.id == instance_id)
    sandbox = match.sandbox
    assert isinstance(sandbox, LocalProcessSandbox)
    return sandbox.workdir


def test_bridge_restart_returns_new_and_previous_instance_ids() -> None:
    """``restart`` must report the replacement id and the id it tore down."""
    bridge = SandboxBridge()
    manager = _LocalBackendManager()
    bridge.attach_manager(manager)

    async def _go() -> tuple[str, dict[str, object], Path]:
        created = await bridge.create(sandbox_type="qemu", qemu_config=QEMUConfig())
        original_id = str(created["instance_id"])
        original_dir = _workdir(manager, original_id)
        restarted = await bridge.restart(original_id, qemu_config=QEMUConfig())
        return original_id, restarted, original_dir

    original_id, restarted, original_dir = _run(_go())

    assert restarted["previous_instance_id"] == original_id
    assert restarted["instance_id"] != original_id
    assert restarted["status"] == "running"
    assert manager.registered_ids() == {str(restarted["instance_id"])}
    assert not original_dir.exists(), "the torn-down sandbox's real work directory must be gone"


def test_bridge_restart_forwards_qemu_config_and_toolbar_config() -> None:
    """The QEMU config and the timeout/network/memory values must reach the backend."""
    bridge = SandboxBridge()
    manager = _LocalBackendManager()
    bridge.attach_manager(manager)
    restart_qemu_config = QEMUConfig()

    async def _go() -> None:
        created = await bridge.create(sandbox_type="qemu", qemu_config=QEMUConfig())
        await bridge.restart(
            str(created["instance_id"]),
            timeout_seconds=123,
            network_enabled=True,
            memory_limit_mb=8192,
            qemu_config=restart_qemu_config,
        )

    _run(_go())

    sandbox_type, qemu_config, config = manager.builds[-1]
    assert sandbox_type == "qemu"
    assert qemu_config is restart_qemu_config, f"restart must forward its QEMU configuration; builds were {manager.builds!r}"
    assert config.timeout_seconds == 123
    assert config.network_enabled is True
    assert config.memory_limit_mb == 8192


def test_bridge_restart_of_unknown_instance_raises_tool_error() -> None:
    """An unknown instance id must surface as a ``ToolError``, not a bare SandboxError."""
    bridge = SandboxBridge()
    manager = _LocalBackendManager()
    bridge.attach_manager(manager)

    async def _go() -> dict[str, object]:
        return await bridge.restart("no-such-instance")

    with pytest.raises(ToolError, match="restart"):
        _run(_go())

    assert manager.builds == [], "an unknown instance must not trigger backend construction"
