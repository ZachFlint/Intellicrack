# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for S17-D10b: ``SandboxBridge.list_guest_processes``.

The Sandbox panel offered "Memory Dump" on the Windows Sandbox backend but
never supplied ``target_pid``, so ``SandboxBridge.memory_dump`` rejected
every Windows instance outright. ``list_guest_processes`` is the new
bridge-level call the GUI's process picker uses to discover a valid PID
before calling ``memory_dump``. These tests drive the real
:class:`SandboxBridge` and a real :class:`SandboxManager` (via
``register_existing_sandbox``), matching the convention in
``tests/sandbox/windows/test_memory_dump_target_pid.py``'s bridge test
class, with a minimal :class:`SandboxBase` test double standing in for the
backend so the bridge's own gating, error wrapping, and return-envelope
logic are exercised in isolation from the Windows-specific PowerShell
plumbing (which has its own dedicated tests in
``tests/sandbox/windows/test_guest_process_listing_s17d10b.py``).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError
from intellicrack.sandbox.base import GuestProcessInfo, SandboxBase, SandboxConfig, SandboxError


if TYPE_CHECKING:
    from collections.abc import Coroutine, Sequence


class _FakeBackend(SandboxBase):
    """Minimal ``SandboxBase`` double that records and controls ``list_processes``.

    Overrides only ``list_processes``; every other ``SandboxBase`` method
    keeps the default "not implemented" behaviour, which is irrelevant here
    since the bridge's ``list_guest_processes`` calls nothing else on it.
    """

    def __init__(
        self,
        processes: Sequence[GuestProcessInfo] | None = None,
        *,
        raises: SandboxError | None = None,
    ) -> None:
        """Initialise the fake backend.

        Args:
            processes: Canned process list to return on success.
            raises: When set, ``list_processes`` raises this instead of
                returning ``processes``.
        """
        super().__init__(SandboxConfig())
        self._processes: list[GuestProcessInfo] = list(processes) if processes is not None else []
        self._raises = raises
        self.list_processes_call_count = 0

    async def list_processes(self) -> list[GuestProcessInfo]:
        """Return the canned processes, or raise the canned error.

        Returns:
            list[GuestProcessInfo]: The configured process list.

        Raises:
            SandboxError: When the double was configured to raise.
        """
        self.list_processes_call_count += 1
        if self._raises is not None:
            raise SandboxError(str(self._raises)) from self._raises
        return list(self._processes)


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


class TestListGuestProcessesWindowsBackend:
    """A Windows Sandbox instance returns the backend's processes in the documented envelope."""

    def test_returns_instance_id_and_process_records(self) -> None:
        """The result dict carries ``instance_id`` and a ``processes`` list matching the backend."""
        bridge = SandboxBridge()
        backend = _FakeBackend(
            processes=[
                GuestProcessInfo(pid=4242, name="notepad.exe", path=r"C:\Windows\notepad.exe"),
                GuestProcessInfo(pid=8, name="System", path=""),
            ],
        )
        instance_id = bridge.register_existing_sandbox(backend, "windows")

        result = _run(bridge.list_guest_processes(instance_id))

        assert result["instance_id"] == instance_id
        assert result["processes"] == [
            {"pid": 4242, "name": "notepad.exe", "path": r"C:\Windows\notepad.exe"},
            {"pid": 8, "name": "System", "path": ""},
        ]
        assert backend.list_processes_call_count == 1

    def test_empty_process_list_returns_an_empty_list_not_an_error(self) -> None:
        """A backend that reports zero processes is not treated as a failure."""
        bridge = SandboxBridge()
        backend = _FakeBackend(processes=[])
        instance_id = bridge.register_existing_sandbox(backend, "windows")

        result = _run(bridge.list_guest_processes(instance_id))

        assert result["instance_id"] == instance_id
        assert result["processes"] == []

    def test_result_has_exactly_the_documented_keys(self) -> None:
        """The result dict has exactly ``instance_id`` and ``processes``, no more, no less."""
        bridge = SandboxBridge()
        backend = _FakeBackend(processes=[GuestProcessInfo(pid=1, name="a", path="")])
        instance_id = bridge.register_existing_sandbox(backend, "windows")

        result = _run(bridge.list_guest_processes(instance_id))

        assert set(result.keys()) == {"instance_id", "processes"}

    def test_each_process_record_has_exactly_pid_name_path(self) -> None:
        """Each entry in ``processes`` has exactly the ``pid``/``name``/``path`` keys."""
        bridge = SandboxBridge()
        backend = _FakeBackend(processes=[GuestProcessInfo(pid=1, name="a.exe", path=r"C:\a.exe")])
        instance_id = bridge.register_existing_sandbox(backend, "windows")

        result = _run(bridge.list_guest_processes(instance_id))

        processes = cast("list[dict[str, object]]", result["processes"])
        assert isinstance(processes, list)
        assert len(processes) == 1
        assert set(processes[0].keys()) == {"pid", "name", "path"}


class TestListGuestProcessesBackendFailure:
    """A ``SandboxError`` raised by the backend must surface as a ``ToolError``."""

    def test_backend_sandbox_error_is_wrapped_as_tool_error(self) -> None:
        """``SandboxError`` from ``list_processes`` becomes a ``ToolError`` naming the failure.

        Falsified by: swallowing the backend's ``SandboxError`` (returning an
        empty list instead of propagating it) would make ``pytest.raises``
        find nothing to catch.
        """
        bridge = SandboxBridge()
        backend = _FakeBackend(raises=SandboxError("guest command failed: access denied"))
        instance_id = bridge.register_existing_sandbox(backend, "windows")

        with pytest.raises(ToolError) as excinfo:
            _run(bridge.list_guest_processes(instance_id))

        message = str(excinfo.value)
        assert "guest command failed: access denied" in message, f"the original backend error text must be preserved: {message}"


class TestListGuestProcessesTypeGating:
    """A non-Windows instance must be rejected without ever reaching the backend."""

    def test_qemu_instance_is_rejected_with_a_clear_message(self) -> None:
        """A QEMU-typed instance raises ``ToolError`` naming the Windows Sandbox requirement."""
        bridge = SandboxBridge()
        backend = _FakeBackend(processes=[GuestProcessInfo(pid=1, name="a", path="")])
        instance_id = bridge.register_existing_sandbox(backend, "qemu")

        with pytest.raises(ToolError) as excinfo:
            _run(bridge.list_guest_processes(instance_id))

        message = str(excinfo.value)
        assert "Windows" in message, f"the rejection must name the Windows Sandbox requirement: {message}"

    def test_qemu_instance_rejection_never_calls_the_backend(self) -> None:
        """The type gate must fire before the backend's ``list_processes`` is ever invoked.

        Falsified by: removing the ``sandbox_type != "windows"`` guard (or
        checking it after the backend call) would make
        ``backend.list_processes_call_count`` end up at 1 instead of 0.
        """
        bridge = SandboxBridge()
        backend = _FakeBackend(processes=[GuestProcessInfo(pid=1, name="a", path="")])
        instance_id = bridge.register_existing_sandbox(backend, "qemu")

        with pytest.raises(ToolError):
            _run(bridge.list_guest_processes(instance_id))

        assert backend.list_processes_call_count == 0, "the QEMU-typed instance must never reach the backend call"


class TestListGuestProcessesUnknownInstance:
    """An unknown ``instance_id`` must raise a clear ``ToolError``."""

    def test_unknown_instance_id_raises_tool_error(self) -> None:
        """Calling with an instance id that was never registered raises ``ToolError``."""
        bridge = SandboxBridge()

        with pytest.raises(ToolError) as excinfo:
            _run(bridge.list_guest_processes("no-such-instance-abc123"))

        message = str(excinfo.value).lower()
        assert "no-such-instance-abc123" in str(excinfo.value) or "not found" in message
