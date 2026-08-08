# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D62: a run must be directable at a named sandbox instance.

``SandboxManager.run_binary`` could only say "make me a new sandbox" or
"reuse an idle one". The reuse branch resolves through ``_find_idle_instance``,
which is a ``next()`` over the instance registry, so with several sandboxes
running every reuse request landed on the first-inserted one. A caller holding
a specific instance - the sandbox panel, which runs the binary in the sandbox
the operator is watching, or the Compare workflow, which needs two runs in two
different instances - had no way to express that.

These tests drive the real :class:`SandboxManager` against the real
:class:`~tests.sandbox.conftest.LocalProcessSandbox` backend. Each managed
instance owns a genuinely separate temporary work directory, and the binary
under test is a real interpreter process that really writes a file into the
directory it was started in. Where the run landed is therefore read back off
the filesystem, not from anything the test arranged.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.manager import SandboxInstance, SandboxManager
from tests.sandbox.conftest import LocalProcessSandbox


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.sandbox.base import SandboxBase
    from intellicrack.sandbox.manager import SandboxType
    from intellicrack.sandbox.qemu import QEMUConfig


_MARKER_NAME = "s17d62-marker.txt"


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
    """Real manager whose backend factory yields real local-process sandboxes.

    Only the concrete backend class is redirected. The locking, the capacity
    accounting, the availability gate, the instance registry and the whole of
    ``run_binary`` are the unmodified production implementation.
    """

    def _build_sandbox(
        self,
        sandbox_type: SandboxType,
        config: SandboxConfig | None = None,
        qemu_config: QEMUConfig | None = None,
    ) -> SandboxBase:
        """Build a real local-process backend.

        Args:
            sandbox_type: Sandbox type requested by the manager.
            config: Generic configuration the manager forwarded.
            qemu_config: QEMU configuration the manager forwarded.

        Returns:
            SandboxBase: A real ``LocalProcessSandbox``.
        """
        del sandbox_type, qemu_config
        return LocalProcessSandbox(config or SandboxConfig())


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


def _marker_args(payload: str) -> list[str]:
    """Build interpreter arguments that write a marker into the process cwd.

    Args:
        payload: Text the spawned process writes into the marker file.

    Returns:
        list[str]: Arguments for the real interpreter binary.
    """
    return ["-c", f"import pathlib; pathlib.Path({_MARKER_NAME!r}).write_text({payload!r}, encoding='utf-8')"]


def test_a_named_instance_receives_the_run() -> None:
    """The run must execute in the instance the caller named, not the first one."""
    manager = _LocalBackendManager()

    async def _go() -> tuple[SandboxInstance, SandboxInstance, str]:
        first = await manager.create(sandbox_type="qemu")
        second = await manager.create(sandbox_type="qemu")
        used, report = await manager.run_binary(
            binary_path=Path(sys.executable),
            args=_marker_args("second"),
            sandbox_type="qemu",
            instance_id=second.id,
            monitor=True,
            reuse_instance=True,
        )
        assert report.exit_code == 0, f"the real interpreter run failed: {report.stderr}"
        return first, second, used.id

    first, second, used_id = _run(_go())

    assert first.id != second.id, "the two managed instances must be genuinely distinct"
    assert used_id == second.id, f"run_binary reported instance {used_id}, but {second.id} was named"

    first_marker = _workdir(first) / _MARKER_NAME
    second_marker = _workdir(second) / _MARKER_NAME
    assert second_marker.is_file(), "the named instance's real work directory must hold the marker the process wrote"
    assert second_marker.read_text(encoding="utf-8") == "second"
    assert not first_marker.exists(), "the unnamed instance must be untouched by a directed run"


def test_a_named_instance_outranks_idle_reuse() -> None:
    """``instance_id`` must win over ``reuse_instance`` for every registered instance."""
    manager = _LocalBackendManager()

    async def _go() -> tuple[list[SandboxInstance], list[str]]:
        instances = [await manager.create(sandbox_type="qemu") for _ in range(3)]
        landed: list[str] = []
        for index, instance in enumerate(instances):
            used, report = await manager.run_binary(
                binary_path=Path(sys.executable),
                args=_marker_args(f"run-{index}"),
                sandbox_type="qemu",
                instance_id=instance.id,
                reuse_instance=True,
            )
            assert report.exit_code == 0, f"the real interpreter run failed: {report.stderr}"
            landed.append(used.id)
        return instances, landed

    instances, landed = _run(_go())

    assert landed == [instance.id for instance in instances], f"each run must land where it was directed; got {landed}"
    for index, instance in enumerate(instances):
        marker = _workdir(instance) / _MARKER_NAME
        assert marker.is_file(), f"instance {index} never ran the binary directed at it"
        assert marker.read_text(encoding="utf-8") == f"run-{index}"


def test_reuse_without_a_name_still_collapses_onto_one_instance() -> None:
    """The undirected reuse path is unchanged, which is exactly why naming is needed.

    This pins the behaviour the fix routes around: with no ``instance_id`` the
    manager keeps taking the first idle instance, so two reuse runs cannot
    produce two comparable reports.
    """
    manager = _LocalBackendManager()

    async def _go() -> tuple[list[SandboxInstance], list[str]]:
        instances = [await manager.create(sandbox_type="qemu") for _ in range(2)]
        landed: list[str] = []
        for index in range(2):
            used, report = await manager.run_binary(
                binary_path=Path(sys.executable),
                args=_marker_args(f"undirected-{index}"),
                sandbox_type="qemu",
                reuse_instance=True,
            )
            assert report.exit_code == 0, f"the real interpreter run failed: {report.stderr}"
            landed.append(used.id)
        return instances, landed

    instances, landed = _run(_go())

    assert landed == [instances[0].id, instances[0].id], f"undirected reuse is expected to collapse; got {landed}"
    assert not (_workdir(instances[1]) / _MARKER_NAME).exists()


def test_naming_an_unknown_instance_fails_loudly() -> None:
    """A directed run at an instance that does not exist must raise, not silently create one."""
    manager = _LocalBackendManager()

    async def _go() -> int:
        await manager.create(sandbox_type="qemu")
        with pytest.raises(SandboxError, match="not found"):
            await manager.run_binary(
                binary_path=Path(sys.executable),
                args=_marker_args("never"),
                sandbox_type="qemu",
                instance_id="intellicrack-s17d62-no-such-instance",
            )
        return len(manager.instances)

    assert _run(_go()) == 1, "a failed directed run must not register an extra sandbox"


def test_naming_a_busy_instance_fails_loudly() -> None:
    """A directed run at an instance already executing a binary must raise."""
    manager = _LocalBackendManager()

    async def _go() -> None:
        instance = await manager.create(sandbox_type="qemu")
        instance.is_busy = True
        with pytest.raises(SandboxError, match="already running"):
            await manager.run_binary(
                binary_path=Path(sys.executable),
                args=_marker_args("never"),
                sandbox_type="qemu",
                instance_id=instance.id,
            )
        assert not (_workdir(instance) / _MARKER_NAME).exists()

    _run(_go())
