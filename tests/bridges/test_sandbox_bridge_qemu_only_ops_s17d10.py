# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Anchor for S17-D10: the bridge operations that only a QEMU instance can serve.

The sandbox panel gates a set of controls on the effective backend being QEMU.
That gating is only correct if the bridge really does refuse those operations
for a non-QEMU instance - otherwise the panel would be disabling controls that
actually work. These tests establish the premise against the real
:class:`SandboxBridge` and a real :class:`SandboxManager`, so the panel gate in
``tests/ui/test_sandbox_panel_backend_gating_s17d10.py`` is anchored to
observed bridge behaviour rather than to an assumption about it.

The manager builds the real :class:`~tests.sandbox.conftest.LocalProcessSandbox`
backend for both types, so the sandboxes genuinely start and stop; the only
thing that differs between the two cases is the ``sandbox_type`` recorded on the
instance, which is exactly the discriminator the bridge branches on.
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

    from intellicrack.sandbox.base import SandboxBase
    from intellicrack.sandbox.manager import SandboxType


_QEMU_ONLY_OPERATIONS: tuple[str, ...] = (
    "screenshot",
    "pcap_start",
    "anti_evasion",
    "extract_dropped_files",
)

_SHARED_OPERATIONS: tuple[str, ...] = (
    "memory_dump",
    "destroy",
)


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

    def _build_sandbox(
        self,
        sandbox_type: SandboxType,
        config: SandboxConfig | None = None,
        qemu_config: QEMUConfig | None = None,
    ) -> SandboxBase:
        """Build a real local-process backend for either sandbox type.

        Args:
            sandbox_type: Sandbox type requested by the manager. Unused: the
                same real backend serves both, so the only difference between
                the cases is the type recorded on the instance.
            config: Generic configuration the manager forwarded.
            qemu_config: QEMU configuration the manager forwarded. Unused by
                the local backend.

        Returns:
            SandboxBase: A real ``LocalProcessSandbox``.
        """
        del sandbox_type, qemu_config
        return LocalProcessSandbox(config or SandboxConfig())


def _instance_of_type(sandbox_type: SandboxType) -> tuple[SandboxBridge, str]:
    """Create a started sandbox instance of the requested type.

    Args:
        sandbox_type: Sandbox type to create through the real bridge.

    Returns:
        tuple[SandboxBridge, str]: The bridge and the created instance id.
    """
    bridge = SandboxBridge()
    bridge.attach_manager(_LocalBackendManager())
    created = _run(
        bridge.create(
            sandbox_type=sandbox_type,
            qemu_config=QEMUConfig() if sandbox_type == "qemu" else None,
        ),
    )
    return bridge, str(created["instance_id"])


def _rejection_message(bridge: SandboxBridge, operation: str, instance_id: str) -> str:
    """Invoke an operation and report the ``ToolError`` text it raised, if any.

    Args:
        bridge: Bridge owning the operation.
        operation: Name of the ``SandboxBridge`` coroutine to invoke.
        instance_id: Instance to invoke the operation against.

    Returns:
        str: The raised ``ToolError`` message, or an empty string when the
        operation did not raise one.
    """
    method = getattr(bridge, operation)
    error: ToolError | None = None
    try:
        _run(method(instance_id))
    except ToolError as exc:
        error = exc
    return "" if error is None else str(error)


@pytest.mark.parametrize("operation", _QEMU_ONLY_OPERATIONS)
def test_bridge_refuses_qemu_only_operation_for_a_windows_instance(operation: str) -> None:
    """Each gated operation must reject a non-QEMU instance with a clear error.

    Args:
        operation: Name of the ``SandboxBridge`` coroutine under test.
    """
    bridge, instance_id = _instance_of_type("windows")

    method = getattr(bridge, operation)
    with pytest.raises(ToolError) as excinfo:
        _run(method(instance_id))

    message = str(excinfo.value)
    assert "QEMU" in message, f"{operation} rejected a Windows instance without naming QEMU: {message}"


@pytest.mark.parametrize("operation", _QEMU_ONLY_OPERATIONS)
def test_bridge_accepts_qemu_only_operation_for_a_qemu_instance(operation: str) -> None:
    """The same operations must not be refused on the QEMU backend.

    This is the half that makes the gate discriminating: if the bridge rejected
    these regardless of type, disabling the controls for QEMU too would be just
    as correct and the panel gate would assert nothing.

    Args:
        operation: Name of the ``SandboxBridge`` coroutine under test.
    """
    bridge, instance_id = _instance_of_type("qemu")

    message = _rejection_message(bridge, operation, instance_id)

    assert "requires QEMU" not in message, f"{operation} refused a QEMU instance as non-QEMU: {message}"


@pytest.mark.parametrize("operation", _SHARED_OPERATIONS)
def test_bridge_does_not_type_gate_the_shared_operations(operation: str) -> None:
    """Operations the panel leaves enabled must not be QEMU-gated.

    Args:
        operation: Name of the ``SandboxBridge`` coroutine under test.
    """
    bridge, instance_id = _instance_of_type("windows")

    message = _rejection_message(bridge, operation, instance_id)

    assert "requires QEMU" not in message, f"{operation} is QEMU-gated but the panel keeps it enabled for Windows: {message}"
