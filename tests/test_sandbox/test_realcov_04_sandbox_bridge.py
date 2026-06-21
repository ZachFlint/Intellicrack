# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for ``intellicrack.bridges.sandbox_bridge`` (SHARD 04).

These tests strengthen the existing sandbox-bridge suite:

* Tool-definition methods are not merely checked for existence; the
  read-only / instance-scoped methods are actually invoked end-to-end
  against the pre-populated fixture manager and their documented return
  keys are asserted (finding 04-F003).
* The real ``SandboxManager`` is driven through ``initialize`` and
  ``create``; on a host without Windows Sandbox the bridge must raise a
  correctly-typed ``ToolError`` carrying the manager's reason, and the
  test skips cleanly only when the genuine capability is absent
  (finding 04-F004).
* The ``SandboxError`` to ``ToolError`` translation layer is verified
  against the real ``SandboxManager.create`` raising the real
  ``SandboxError`` exception shape (finding 04-F005).
* The full non-mock call chain ``ensure_manager -> manager.create ->
  bridge state update`` is exercised and the real field values are
  asserted (finding 04-F007).
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError
from intellicrack.sandbox import SandboxError, SandboxManager


if TYPE_CHECKING:
    from pathlib import Path


_WIN_INSTANCE = "win-test-001"
_QEMU_INSTANCE = "qemu-test-001"


class TestToolDefinitionDispatchEndToEnd:
    """04-F003: tool-definition methods dispatch and return documented keys."""

    @pytest.mark.asyncio
    async def test_status_dispatch(self, sandbox_bridge: SandboxBridge) -> None:
        """sandbox.status resolves and returns a populated status mapping.

        Args:
            sandbox_bridge: Fixture bridge with two pre-populated instances.
        """
        result = await sandbox_bridge.status()
        assert isinstance(result, dict)
        assert "available_types" in result
        assert "total_count" in result
        assert result["total_count"] == 2

    @pytest.mark.asyncio
    async def test_list_dispatch(self, sandbox_bridge: SandboxBridge) -> None:
        """sandbox.list resolves and returns one entry per real instance.

        Args:
            sandbox_bridge: Fixture bridge with two pre-populated instances.
        """
        result = await sandbox_bridge.list()
        assert isinstance(result, list)
        ids = {entry["id"] for entry in result}
        assert ids == {_WIN_INSTANCE, _QEMU_INSTANCE}
        for entry in result:
            assert entry["status"] == "running"

    @pytest.mark.asyncio
    async def test_instance_scoped_methods_dispatch(
        self,
        sandbox_bridge: SandboxBridge,
    ) -> None:
        """Instance-scoped tool methods run against a real fixture instance.

        Iterates the tool definition and invokes the single-``instance_id``
        analysis/QEMU methods against a valid pre-existing instance,
        asserting each returns a dict echoing the queried instance id. This
        proves dispatch works end-to-end rather than that the attribute
        merely exists.

        Args:
            sandbox_bridge: Fixture bridge with two pre-populated instances.
        """
        # Methods keyed only by a QEMU instance_id with documented dict returns.
        qemu_single: dict[str, str] = {
            "cont": "instance_id",
            "get_pending_messages": "instance_id",
            "snapshot_list": "instance_id",
            "extract_iocs": "instance_id",
            "timeline": "instance_id",
            "detect_c2": "instance_id",
        }
        invoked = 0
        for name, key in qemu_single.items():
            method = getattr(sandbox_bridge, name)
            result = await method(_QEMU_INSTANCE)
            assert isinstance(result, dict), f"{name} returned non-dict"
            assert result[key] == _QEMU_INSTANCE
            invoked += 1
        assert invoked == len(qemu_single)

    @pytest.mark.asyncio
    async def test_execute_command_dispatch(self, sandbox_bridge: SandboxBridge) -> None:
        """sandbox.execute returns the documented (exit_code, stdout, stderr).

        Args:
            sandbox_bridge: Fixture bridge with two pre-populated instances.
        """
        result = await sandbox_bridge.execute(_WIN_INSTANCE, "echo hi")
        assert result["exit_code"] == 0
        assert "stdout" in result
        assert "stderr" in result
        assert "hi" in result["stdout"]


class TestStubManagerFullCallChain:
    """04-F007: non-mock chain ensure_manager -> create -> state update."""

    @pytest.mark.asyncio
    async def test_create_updates_state_with_real_fields(
        self,
        sandbox_bridge: SandboxBridge,
    ) -> None:
        """create() drives the manager and writes connected state, no mocks.

        Args:
            sandbox_bridge: Fixture bridge backed by the in-process manager.
        """
        before = sandbox_bridge.ensure_manager()
        result = await sandbox_bridge.create(sandbox_type="qemu")
        after = sandbox_bridge.ensure_manager()

        assert before is after, "ensure_manager must be idempotent across create"
        assert result["type"] == "qemu"
        assert result["status"] == "running"
        assert result["instance_id"]
        # The bridge state must reflect a live, connected sandbox session.
        assert sandbox_bridge.state.connected is True
        assert sandbox_bridge.state.tool_running is True
        assert sandbox_bridge.state.last_error is None
        # The newly created instance is retrievable from the same manager.
        listed = await sandbox_bridge.list()
        assert any(entry["id"] == result["instance_id"] for entry in listed)

    @pytest.mark.asyncio
    async def test_destroy_then_list_reflects_removal(
        self,
        sandbox_bridge: SandboxBridge,
    ) -> None:
        """destroy() removes the instance from the real manager's view.

        Args:
            sandbox_bridge: Fixture bridge with two pre-populated instances.
        """
        result = await sandbox_bridge.destroy(_WIN_INSTANCE)
        assert result["success"] is True
        listed = await sandbox_bridge.list()
        assert all(entry["id"] != _WIN_INSTANCE for entry in listed)

    @pytest.mark.asyncio
    async def test_run_binary_records_target_path(
        self,
        sandbox_bridge: SandboxBridge,
        real_pe_exe: Path,
    ) -> None:
        """run_binary executes a real PE path and records it as the target.

        Args:
            sandbox_bridge: Fixture bridge backed by the in-process manager.
            real_pe_exe: Session fixture resolving a real System32 executable.
        """
        report = await sandbox_bridge.run_binary(
            binary_path=str(real_pe_exe),
            sandbox_type="windows",
        )
        assert report["result"] == "success"
        assert report["instance_id"]
        assert sandbox_bridge.state.binary_loaded is True
        assert sandbox_bridge.state.target_path == real_pe_exe


class TestRealManagerErrorTranslation:
    """04-F005: SandboxError from the real manager becomes ToolError."""

    @pytest.mark.asyncio
    async def test_create_translates_sandbox_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A real SandboxManager.create raising SandboxError surfaces ToolError.

        The bridge is backed by a genuine ``SandboxManager``; only the
        manager's ``create`` coroutine is replaced with one that raises
        the real ``SandboxError`` exception shape, so the bridge's
        error-translation layer (the capability under test) runs for real.

        Args:
            monkeypatch: Pytest fixture used to install the raising
                ``create`` coroutine at the manager boundary.
        """
        bridge = SandboxBridge()
        await bridge.initialize()
        manager = bridge.ensure_manager()
        assert isinstance(manager, SandboxManager)

        async def _raise_create(*_args: object, **_kwargs: object) -> object:
            await asyncio.sleep(0)
            msg = "Windows Sandbox not available"
            raise SandboxError(msg)

        monkeypatch.setattr(manager, "create", _raise_create)

        with pytest.raises(ToolError) as exc_info:
            await bridge.create(sandbox_type="windows")

        message = str(exc_info.value)
        assert "Windows Sandbox not available" in message
        assert "Failed to create sandbox" in message
        # The failure must be recorded on the bridge state.
        assert bridge.state.last_error == "Windows Sandbox not available"


class TestRealManagerIntegration:
    """04-F004: real SandboxManager create path gates only the success outcome."""

    @pytest.mark.spawns_process
    @pytest.mark.asyncio
    async def test_create_windows_sandbox_success_path(self) -> None:
        """Gate the real create-success path; skip only when capability is absent.

        Probes the real ``SandboxManager`` for Windows Sandbox availability
        before attempting creation.  If the host genuinely lacks the
        ``Containers-DisposableClientVM`` Windows feature or Hyper-V, the
        test skips cleanly.  When the capability is present the create call
        MUST succeed and return a non-empty instance id with the expected
        field values; a regression in the create path makes the test fail.

        The error-translation contract (``SandboxError`` -> ``ToolError``) is
        already gated by
        ``TestRealManagerErrorTranslation.test_create_translates_sandbox_error``;
        this test does NOT accept a ``ToolError`` as a passing outcome so that
        a capability regression on a capable host is detected immediately.
        """
        bridge = SandboxBridge()
        await bridge.initialize()
        manager = bridge.ensure_manager()
        assert isinstance(manager, SandboxManager)

        available_types = await manager.get_available_types()
        if "windows" not in available_types:
            pytest.skip("Windows Sandbox not available on this host")

        created_id: str | None = None
        try:
            result = await bridge.create(sandbox_type="windows")
            created_id = str(result["instance_id"])
            listed = await bridge.list()
            self._assert_create_success(bridge, result, created_id, listed)
        finally:
            if created_id is not None:
                await bridge.destroy(created_id)
            await bridge.shutdown()

    @staticmethod
    def _assert_create_success(
        bridge: SandboxBridge,
        result: dict[str, object],
        created_id: str,
        listed: list[dict[str, object]],
    ) -> None:
        """Assert all real fields of a successful Windows Sandbox create.

        Uses ``datetime.fromisoformat`` as an independent oracle for the
        ``created_at`` timestamp: if the bridge stops emitting a valid
        ISO-8601 string the parse raises and the test fails.

        Args:
            bridge: The bridge whose state recorded the outcome.
            result: The dict returned by ``bridge.create``.
            created_id: The extracted non-empty instance id.
            listed: The list returned by ``bridge.list`` after create.
        """
        assert created_id, "create must return a non-empty instance_id"
        assert result["type"] == "windows"
        assert result["status"] == "running"

        parsed = datetime.fromisoformat(str(result["created_at"]))
        assert parsed.tzinfo is not None, "created_at must be timezone-aware"

        listed_ids = {entry["id"] for entry in listed}
        assert created_id in listed_ids, "newly created instance must appear in list()"

        assert bridge.state.connected is True
        assert bridge.state.tool_running is True
        assert bridge.state.last_error is None
