# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D14: ``SandboxManager.restart`` must own the teardown/recreate.

Before this fix the manager had ``create`` and ``destroy`` but no ``restart``,
so the sandbox panel synthesised one by chaining two bridge calls across four
callbacks. The failure semantics of the window between the teardown and the
recreate therefore lived in the GUI, where they could neither be reused
headlessly nor tested.

These tests drive the real :class:`SandboxManager` against the real
:class:`~tests.sandbox.conftest.LocalProcessSandbox` backend, which does
genuine work: ``start`` creates a real temporary work directory and ``stop``
removes it. A restart is therefore observed through real filesystem state - the
old work directory is really gone and a different real directory exists
afterwards - rather than through anything the test fabricates.

The recreate-failure case uses a real availability probe that genuinely fails
(it looks for an executable that is truly absent from the host), so the manager
takes its real "type not available" branch.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.manager import SandboxInstance, SandboxManager
from intellicrack.sandbox.qemu import QEMUConfig
from tests.sandbox.conftest import LocalProcessSandbox


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.sandbox.base import SandboxBase
    from intellicrack.sandbox.manager import SandboxType


_ABSENT_TOOL = "intellicrack-restart-gate-absent-tool"


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


class _UnavailableLocalSandbox(LocalProcessSandbox):
    """Real local sandbox that probes as unavailable on this host.

    The unmodified availability contract runs for real: the probe looks for an
    executable that genuinely does not exist, which is the same outcome a host
    without the backend installed produces.
    """

    async def is_available(self) -> bool:
        """Probe the host for an executable that is genuinely absent.

        Returns:
            bool: ``False`` on any host that does not carry the probe tool.
        """
        return shutil.which(_ABSENT_TOOL) is not None


class _LocalBackendManager(SandboxManager):
    """Real manager whose backend factory yields real local-process sandboxes.

    Only the concrete backend class is redirected; every other part of
    ``create``/``destroy``/``restart`` - the locking, the capacity accounting,
    the availability gate, the auto-start, and the instance registry - is the
    unmodified production implementation.
    """

    def __init__(self, default_config: SandboxConfig | None = None) -> None:
        """Initialise the manager and its build recorder.

        Args:
            default_config: Optional default sandbox configuration.
        """
        super().__init__(default_config=default_config)
        self.builds: list[tuple[SandboxType, QEMUConfig | None]] = []
        self.fail_next_build: bool = False

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
            SandboxBase: A real ``LocalProcessSandbox``, or one that probes as
            unavailable when the test has armed a recreate failure.
        """
        self.builds.append((sandbox_type, qemu_config))
        effective = config or SandboxConfig()
        if self.fail_next_build:
            return _UnavailableLocalSandbox(effective)
        return LocalProcessSandbox(effective)

    def registered_ids(self) -> set[str]:
        """Report the identifiers the manager currently tracks.

        Returns:
            set[str]: Registered instance identifiers.
        """
        return set(self._instances)


def _workdir(instance: SandboxInstance) -> Path:
    """Read the real work directory of a managed local-process sandbox.

    Args:
        instance: Managed instance wrapping a ``LocalProcessSandbox``.

    Returns:
        Path: The sandbox's real work directory.
    """
    sandbox = instance.sandbox
    assert isinstance(sandbox, LocalProcessSandbox)
    return sandbox.workdir


def test_restart_replaces_the_instance_and_its_real_workdir() -> None:
    """A restart must tear the real sandbox down and bring a fresh real one up."""
    manager = _LocalBackendManager()

    async def _go() -> tuple[SandboxInstance, Path, SandboxInstance, Path]:
        original = await manager.create(sandbox_type="qemu")
        original_dir = _workdir(original)
        replacement = await manager.restart(original.id)
        return original, original_dir, replacement, _workdir(replacement)

    original, original_dir, replacement, replacement_dir = _run(_go())

    assert replacement.id != original.id, "restart must produce a genuinely new instance"
    assert manager.registered_ids() == {replacement.id}, f"only the replacement may remain registered; got {manager.registered_ids()}"
    assert not original_dir.exists(), "the original sandbox's real work directory must be removed"
    assert replacement_dir.exists(), "the replacement sandbox must have started for real"
    assert replacement_dir != original_dir
    assert replacement.state.status == "running"
    assert original.state.status == "stopped"


def test_restart_preserves_type_and_binary_path() -> None:
    """The replacement must inherit the original's sandbox type and binary path."""
    manager = _LocalBackendManager()
    binary = Path("C:/samples/target.exe")

    async def _go() -> tuple[SandboxInstance, SandboxInstance]:
        original = await manager.create(sandbox_type="windows", binary_path=binary)
        replacement = await manager.restart(original.id)
        return original, replacement

    original, replacement = _run(_go())

    assert replacement.sandbox_type == original.sandbox_type == "windows"
    assert replacement.binary_path == binary, "the analysed binary association must survive a restart"


def test_restart_forwards_qemu_config_to_the_backend() -> None:
    """The QEMU configuration must reach the backend factory on the recreate.

    This is the S17-D06 regression guard: a restart path that drops
    ``qemu_config`` would rebuild a QEMU sandbox with no disk image, which can
    never boot.
    """
    manager = _LocalBackendManager()
    qemu_config = QEMUConfig()

    async def _go() -> SandboxInstance:
        original = await manager.create(sandbox_type="qemu")
        return await manager.restart(original.id, qemu_config=qemu_config)

    _run(_go())

    assert manager.builds[-1][0] == "qemu"
    assert manager.builds[-1][1] is qemu_config, (
        f"restart must forward the QEMU configuration to the backend; builds were {manager.builds!r}"
    )


def test_restart_applies_the_supplied_config_to_the_replacement() -> None:
    """A configuration override handed to restart must reach the new backend."""
    manager = _LocalBackendManager()
    replacement_config = SandboxConfig(timeout_seconds=17, network_enabled=True, memory_limit_mb=4096)

    async def _go() -> SandboxInstance:
        original = await manager.create(sandbox_type="qemu")
        return await manager.restart(original.id, config=replacement_config)

    replacement = _run(_go())

    assert replacement.sandbox.config.timeout_seconds == 17
    assert replacement.sandbox.config.memory_limit_mb == 4096
    assert replacement.sandbox.config.network_enabled is True


def test_recreate_failure_leaves_no_registered_instance() -> None:
    """A recreate failure after teardown must leave the manager holding nothing."""
    manager = _LocalBackendManager()

    async def _go() -> tuple[str, Path]:
        original = await manager.create(sandbox_type="qemu")
        original_dir = _workdir(original)
        manager.fail_next_build = True
        with pytest.raises(SandboxError):
            await manager.restart(original.id)
        return original.id, original_dir

    original_id, original_dir = _run(_go())

    assert manager.registered_ids() == set(), (
        f"a failed recreate must not leave a stale instance registered; got {manager.registered_ids()}"
    )
    assert original_id not in manager.registered_ids()
    assert not original_dir.exists(), "the original sandbox must still have been torn down for real"
    assert manager.active_count == 0


def test_restart_of_unknown_instance_raises_and_creates_nothing() -> None:
    """Restarting an unknown identifier must raise and must not build a backend."""
    manager = _LocalBackendManager()

    async def _go() -> None:
        await manager.restart("no-such-instance")

    with pytest.raises(SandboxError, match="no-such-instance"):
        _run(_go())

    assert manager.builds == [], "an unknown instance must not trigger any backend construction"
    assert manager.registered_ids() == set()
