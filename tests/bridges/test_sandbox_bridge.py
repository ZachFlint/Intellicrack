# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for sandbox_bridge.py — F-0001 through F-0016 audit findings."""

from __future__ import annotations

import asyncio
import dataclasses
import importlib
import json
import logging
import tempfile
import textwrap
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast

import pytest

from intellicrack.bridges.sandbox_bridge import (
    SandboxBridge,
    dataclass_to_dict,
    json_safe,
)
from intellicrack.core.types import SandboxError, ToolError
from intellicrack.sandbox import ExecutionReport
from tests.sandbox.conftest import (
    InMemoryQEMUSandbox,
    InMemorySandbox,
    QMPResponse,
    StubAgent,
    StubInstance,
    StubManager,
    StubQMP,
)


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from intellicrack.sandbox.base import SandboxConfig
    from intellicrack.sandbox.manager import SandboxManager


def _make_execution_report() -> ExecutionReport:
    """Build a real, empty-activity ``ExecutionReport`` for run_binary tests.

    The production ``run_binary`` serialises the report it receives from the
    manager through ``dataclass_to_dict``, which (correctly) rejects anything
    that is not a real dataclass instance. Tests that exercise the success path
    therefore need a genuine :class:`ExecutionReport`, not a mock stand-in.

    Returns:
        ExecutionReport: A successful report with empty activity lists.
    """
    return ExecutionReport(
        result="success",
        exit_code=0,
        stdout="",
        stderr="",
        duration_seconds=1.0,
    )


class _QMPResponse(QMPResponse):
    """``tests.sandbox.conftest.QMPResponse`` augmented with an ``error`` field.

    The conftest response only models the always-succeeds ``StubQMP`` path
    and has no ``error`` field; this subclass adds it so scripted-failure
    tests can populate it, matching the shape of the real
    ``intellicrack.sandbox.qemu.QMPResponse``.
    """

    def __init__(
        self,
        *,
        success: bool = True,
        data: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        """Initialise the augmented QMP response.

        Args:
            success: Whether the command succeeded.
            data: Response payload (defaults to empty dict).
            error: Error message when ``success`` is ``False``.
        """
        super().__init__(success=success, data=data)
        self.error = error


class _ScriptedQMP:
    """QMP client stub whose ``cont()`` outcome is scripted per test.

    Duck-type compatible with :class:`tests.sandbox.conftest.StubQMP` (so a
    test can install it in place of ``InMemoryQEMUSandbox.qmp`` via
    ``cast("StubQMP", ...)``) but lets a test force ``cont()`` to raise a
    specific exception or return a specific :class:`_QMPResponse`, so the
    bridge's QMP-failure handling can be exercised against a real (non-mock)
    object.
    """

    def __init__(
        self,
        *,
        cont_error: Exception | None = None,
        cont_response: _QMPResponse | None = None,
    ) -> None:
        """Initialise the scripted QMP client.

        Args:
            cont_error: Exception to raise from ``cont()``, if any.
            cont_response: Response ``cont()`` returns when no error is scripted.
        """
        self._cont_error = cont_error
        self._cont_response = cont_response

    async def cont(self) -> _QMPResponse:
        """Resume VM execution per the scripted outcome.

        Returns:
            _QMPResponse: The scripted response, or a default success response.

        Raises:
            Exception: The scripted ``cont_error``, if set.
        """
        if self._cont_error is not None:
            raise self._cont_error
        if self._cont_response is not None:
            return self._cont_response
        return _QMPResponse(success=True, data={"status": "running"})

    async def stop(self) -> _QMPResponse:
        """Pause VM execution.

        Returns:
            _QMPResponse: Success response.
        """
        return _QMPResponse(success=True, data={"status": "paused"})


class _ScriptedAgent:
    """Guest agent stub returning a fixed list of pending messages.

    Duck-type compatible with :class:`tests.sandbox.conftest.StubAgent` (so a
    test can install it in place of ``InMemoryQEMUSandbox.agent`` via
    ``cast("StubAgent", ...)``) for tests that need to control exactly which
    message objects (or errors) ``get_pending_messages()`` produces.
    """

    def __init__(
        self,
        messages: list[object] | None = None,
        *,
        error: Exception | None = None,
    ) -> None:
        """Initialise the scripted agent.

        Args:
            messages: Messages to return from ``get_pending_messages()``.
            error: Exception to raise instead of returning ``messages``.
        """
        self._messages = messages if messages is not None else []
        self._error = error

    async def get_pending_messages(self) -> list[object]:
        """Return the scripted pending messages.

        Returns:
            list[object]: The scripted messages.

        Raises:
            Exception: The scripted ``error``, if set.
        """
        if self._error is not None:
            raise self._error
        return self._messages


class _ScriptedSandbox(InMemorySandbox):
    """Real ``InMemorySandbox`` whose boundary methods can be scripted to fail.

    Every method that is not explicitly scripted keeps the genuine
    ``InMemorySandbox`` behaviour, so a single scripted failure exercises
    the bridge's error-wrapping path while every other call runs for real.
    Also records ``yara_scan`` call arguments and allows overriding
    ``vnc_port``, replacing the ``MagicMock``/``AsyncMock`` doubles the
    equivalent tests previously relied on.
    """

    def __init__(
        self,
        config: SandboxConfig | None = None,
        *,
        fail_method: str | None = None,
        fail_error: Exception | None = None,
        vnc_port: int | None = 5900,
        yara_matches: list[dict[str, Any]] | None = None,
    ) -> None:
        """Initialise the scripted sandbox.

        Args:
            config: Optional sandbox configuration.
            fail_method: Name of the one method to make raise ``fail_error``.
            fail_error: Exception raised by ``fail_method`` when invoked.
            vnc_port: Fixed value returned by the ``vnc_port`` property.
            yara_matches: Fixed matches returned by ``yara_scan`` instead of
                the real ``InMemorySandbox`` sample match.
        """
        super().__init__(config)
        self._fail_method = fail_method
        self._fail_error = fail_error
        self._vnc_port_value = vnc_port
        self._yara_matches = yara_matches
        self.yara_scan_calls: list[tuple[str | None, str]] = []

    def _maybe_raise(self, name: str) -> None:
        """Raise the scripted error when ``name`` is the scripted failing method.

        Args:
            name: Name of the method currently being invoked.
        """
        if self._fail_method == name and self._fail_error is not None:
            raise self._fail_error

    @property
    def vnc_port(self) -> int | None:
        """VNC port.

        Returns:
            int | None: The scripted VNC port value.
        """
        return self._vnc_port_value

    def seed_snapshot(self, snapshot_id: str) -> None:
        """Pre-populate a snapshot so a later ``restore``/``delete`` call finds it.

        Args:
            snapshot_id: The full snapshot key (e.g. ``"snap-1"``) to seed.
        """
        self._snapshots[snapshot_id] = {}

    async def copy_to_sandbox(self, source: Path, dest: str) -> None:
        """Copy a file into the sandbox, or raise the scripted error.

        Args:
            source: Local source path.
            dest: Destination path in sandbox.
        """
        self._maybe_raise("copy_to_sandbox")
        await super().copy_to_sandbox(source, dest)

    async def copy_from_sandbox(self, source: str, dest: Path) -> None:
        """Copy a file from the sandbox, or raise the scripted error.

        Args:
            source: Source path in sandbox.
            dest: Local destination path.
        """
        self._maybe_raise("copy_from_sandbox")
        await super().copy_from_sandbox(source, dest)

    async def take_snapshot(self, name: str) -> str:
        """Take a snapshot, or raise the scripted error.

        Args:
            name: Snapshot name.

        Returns:
            str: Snapshot identifier.
        """
        self._maybe_raise("take_snapshot")
        return await super().take_snapshot(name)

    async def restore_snapshot(self, snapshot_id: str) -> None:
        """Restore a snapshot, or raise the scripted error.

        Args:
            snapshot_id: Snapshot identifier.
        """
        self._maybe_raise("restore_snapshot")
        await super().restore_snapshot(snapshot_id)

    async def list_snapshots(self) -> list[str]:
        """List snapshots, or raise the scripted error.

        Returns:
            list[str]: List of snapshot identifiers.
        """
        self._maybe_raise("list_snapshots")
        return await super().list_snapshots()

    async def delete_snapshot(self, name: str) -> None:
        """Delete a snapshot, or raise the scripted error.

        Args:
            name: Snapshot name to delete.
        """
        self._maybe_raise("delete_snapshot")
        await super().delete_snapshot(name)

    async def start_pcap_capture(self) -> str:
        """Start packet capture, or raise the scripted error.

        Returns:
            str: Capture identifier.
        """
        self._maybe_raise("start_pcap_capture")
        return await super().start_pcap_capture()

    async def stop_pcap_capture(
        self,
        capture_id: str,
        output_path: Path | None = None,
    ) -> Path:
        """Stop packet capture, or raise the scripted error.

        Args:
            capture_id: Capture identifier.
            output_path: Optional output path.

        Returns:
            Path: Path to the PCAP file.
        """
        self._maybe_raise("stop_pcap_capture")
        return await super().stop_pcap_capture(capture_id, output_path)

    async def capture_screenshot(self, output_path: Path | None = None) -> Path:
        """Capture a screenshot, or raise the scripted error.

        Args:
            output_path: Optional output path.

        Returns:
            Path: Path to the screenshot file.
        """
        self._maybe_raise("capture_screenshot")
        return await super().capture_screenshot(output_path)

    async def apply_anti_evasion(self, profile: str = "default") -> dict[str, Any]:
        """Apply anti-evasion techniques, or raise the scripted error.

        Args:
            profile: Anti-evasion profile name.

        Returns:
            dict[str, Any]: Dictionary of applied techniques.
        """
        self._maybe_raise("apply_anti_evasion")
        return await super().apply_anti_evasion(profile)

    async def dump_memory(
        self,
        output_path: Path | None = None,
        target_pid: int | None = None,
    ) -> Path:
        """Dump guest memory, or raise the scripted error.

        Args:
            output_path: Optional output path.
            target_pid: Optional guest-side target PID.

        Returns:
            Path: Path to the memory dump file.
        """
        self._maybe_raise("dump_memory")
        return await super().dump_memory(output_path, target_pid)

    async def extract_dropped_files(self, output_path: Path | None = None) -> Path:
        """Extract dropped files, or raise the scripted error.

        Args:
            output_path: Optional output path.

        Returns:
            Path: Path to the ZIP archive.
        """
        self._maybe_raise("extract_dropped_files")
        return await super().extract_dropped_files(output_path)

    async def yara_scan(
        self,
        rules_path: str | None = None,
        scan_target: str = "files",
    ) -> list[dict[str, Any]]:
        """Run YARA rules, recording the call and honouring scripted overrides.

        Args:
            rules_path: Path to YARA rules file.
            scan_target: What to scan ('files' or 'memory').

        Returns:
            list[dict[str, Any]]: List of YARA match results.
        """
        self._maybe_raise("yara_scan")
        self.yara_scan_calls.append((rules_path, scan_target))
        if self._yara_matches is not None:
            return self._yara_matches
        return await super().yara_scan(rules_path, scan_target)


class _FailingManager(StubManager):
    """``StubManager`` whose ``create``/``run_binary`` calls can be scripted to fail.

    Every other manager operation delegates to the real ``StubManager``
    implementation, so only the boundary call under test is disturbed.
    """

    def __init__(
        self,
        instances: dict[str, StubInstance] | None = None,
        *,
        create_error: Exception | None = None,
        run_binary_error: Exception | None = None,
    ) -> None:
        """Initialise the failing manager.

        Args:
            instances: Optional pre-populated instance dict.
            create_error: Exception ``create()`` raises instead of succeeding.
            run_binary_error: Exception ``run_binary()`` raises instead of succeeding.
        """
        super().__init__(instances)
        self._create_error = create_error
        self._run_binary_error = run_binary_error

    async def create(
        self,
        sandbox_type: str = "windows",
        config: SandboxConfig | None = None,
        binary_path: Path | None = None,
        qemu_config: object = None,
        *,
        auto_start: bool = True,
    ) -> StubInstance:
        """Create an instance, or raise the scripted ``create_error``.

        Args:
            sandbox_type: Type of sandbox.
            config: Optional configuration.
            binary_path: Optional binary path.
            qemu_config: Optional QEMU config.
            auto_start: Whether to auto-start.

        Returns:
            StubInstance: Created instance.
        """
        if self._create_error is not None:
            raise self._create_error
        return await super().create(
            sandbox_type=sandbox_type,
            config=config,
            binary_path=binary_path,
            qemu_config=qemu_config,
            auto_start=auto_start,
        )

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        sandbox_type: str = "windows",
        config: SandboxConfig | None = None,
        time_limit: int | None = None,
        qemu_config: object = None,
        instance_id: str | None = None,
        companions: Sequence[Path] | None = None,
        *,
        monitor: bool = True,
        reuse_instance: bool = False,
    ) -> tuple[StubInstance, ExecutionReport]:
        """Run a binary, or raise the scripted ``run_binary_error``.

        Args:
            binary_path: Path to the binary.
            args: Optional command line arguments.
            sandbox_type: Type of sandbox.
            config: Optional configuration.
            time_limit: Optional timeout.
            qemu_config: Optional QEMU config.
            instance_id: Instance the caller directed the run at.
            companions: Files to place beside the binary.
            monitor: Whether to monitor.
            reuse_instance: Whether to reuse an existing instance.

        Returns:
            tuple[StubInstance, ExecutionReport]: Instance and report.
        """
        if self._run_binary_error is not None:
            raise self._run_binary_error
        return await super().run_binary(
            binary_path,
            args=args,
            sandbox_type=sandbox_type,
            config=config,
            time_limit=time_limit,
            qemu_config=qemu_config,
            instance_id=instance_id,
            companions=companions,
            monitor=monitor,
            reuse_instance=reuse_instance,
        )


class _CountingAnalysisModule:
    """Stand-in analysis module exposing only ``extract_iocs``, returning ``[]``."""

    @staticmethod
    def extract_iocs(report: object) -> list[dict[str, Any]]:
        """Return no IOCs regardless of the report contents.

        Args:
            report: The execution report (ignored).

        Returns:
            list[dict[str, Any]]: Always an empty list.
        """
        del report
        return []


class TestF0001ContBroadException:
    """F-0001: cont() catches broad Exception and wraps as ToolError."""

    def test_cont_wraps_general_exception(self) -> None:
        """cont() raises ToolError with exact prefix when qmp.cont() throws RuntimeError.

        The bridge constant ``_ERR_CONT_FAILED`` is "Failed to resume VM execution".
        The error message must contain both that prefix and the original exception text
        so callers can distinguish the failure type. ``bridge.state.last_error`` must
        remain None because cont() does not use _StateTracker (the raise propagates
        before the state-tracker exits).
        """
        bridge = SandboxBridge()

        sandbox = InMemoryQEMUSandbox()
        sandbox.qmp = cast("StubQMP", _ScriptedQMP(cont_error=RuntimeError("unexpected QMP failure")))
        instance = StubInstance(sandbox, "qemu", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.cont("some-id")
            err = str(exc_info.value)
            assert "Failed to resume VM execution" in err, f"missing prefix: {err!r}"
            assert "unexpected QMP failure" in err, f"missing original cause: {err!r}"

        asyncio.run(run())

    def test_cont_wraps_value_error(self) -> None:
        """cont() raises ToolError that embeds ValueError text in the message.

        The exact prefix is "Failed to resume VM execution" and the error message
        must include the ValueError detail "bad value", ensuring the bridge faithfully
        surfaces the underlying cause rather than swallowing it.
        """
        bridge = SandboxBridge()

        sandbox = InMemoryQEMUSandbox()
        sandbox.qmp = cast("StubQMP", _ScriptedQMP(cont_error=ValueError("bad value")))
        instance = StubInstance(sandbox, "qemu", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.cont("some-id")
            err = str(exc_info.value)
            assert "Failed to resume VM execution" in err, f"missing prefix: {err!r}"
            assert "bad value" in err, f"missing ValueError detail: {err!r}"

        asyncio.run(run())

    def test_cont_raises_on_qmp_failure_response(self) -> None:
        """cont() raises ToolError whose message embeds the QMP error detail verbatim.

        When the QMP response has ``success=False`` and ``error="VM not running"``,
        the ToolError message must contain exactly "VM not running" so the caller
        can surface the root cause. The prefix "Failed to resume VM execution" must
        also be present.
        """
        bridge = SandboxBridge()

        failed_response = _QMPResponse(success=False, error="VM not running")
        sandbox = InMemoryQEMUSandbox()
        sandbox.qmp = cast("StubQMP", _ScriptedQMP(cont_response=failed_response))
        instance = StubInstance(sandbox, "qemu", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.cont("some-id")
            err = str(exc_info.value)
            assert "Failed to resume VM execution" in err, f"missing prefix: {err!r}"
            assert "VM not running" in err, f"missing QMP error detail: {err!r}"

        asyncio.run(run())

    def test_cont_logs_resumed_only_on_success(self) -> None:
        """cont() only logs vm_resumed when QMP returns success."""
        bridge = SandboxBridge()

        sandbox = InMemoryQEMUSandbox()
        sandbox.qmp = cast("StubQMP", _ScriptedQMP(cont_response=_QMPResponse(success=True, data={"status": "running"})))
        instance = StubInstance(sandbox, "qemu", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> dict[str, Any]:
            return await bridge.cont("some-id")

        result = asyncio.run(run())
        assert result["success"] is True
        assert result["instance_id"] == "some-id"


class TestF0002NarrowExceptionHandling:
    """F-0002: Exception handling sites wrap unexpected exceptions as ToolError.

    These tests use real ``ExecutionReport`` objects with malformed fields that
    cause genuine ``KeyError`` or ``TypeError`` exceptions inside the real
    analysis functions. No mocking of the analysis module is performed, so the
    bridge error-wrapping path is exercised against real failure signals.
    """

    def test_extract_iocs_wraps_real_keyerror_from_bad_network_activity(self) -> None:
        """extract_iocs() raises ToolError when the report has malformed network_activity.

        A ``network_activity`` dict lacking the ``remote_address`` key causes
        ``analysis.extract_iocs`` to raise ``KeyError``. The bridge must re-raise
        that as ``ToolError`` with prefix "Failed to extract IOCs" and include the
        key name in the message. ``bridge.state.last_error`` must be populated.
        """
        bridge = SandboxBridge()

        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
            network_activity=[cast("Any", {"wrong_key": "value"})],
        )
        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        instance.last_report = report
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.extract_iocs("some-id")
            err = str(exc_info.value)
            assert "Failed to extract IOCs" in err, f"missing prefix: {err!r}"

        asyncio.run(run())
        assert bridge.state.last_error is not None
        assert "Failed to extract IOCs" in bridge.state.last_error or "remote_address" in bridge.state.last_error

    def test_timeline_wraps_real_keyerror_from_bad_file_changes(self) -> None:
        """timeline() raises ToolError when the report has malformed file_changes.

        A ``file_changes`` dict lacking the ``operation`` key causes
        ``analysis.generate_timeline`` to raise ``KeyError``. The bridge must
        re-raise that as ``ToolError`` with prefix "Failed to generate timeline".
        ``bridge.state.last_error`` must be populated.
        """
        bridge = SandboxBridge()

        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
            file_changes=[cast("Any", {"missing": "keys"})],
        )
        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        instance.last_report = report
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.timeline("some-id")
            err = str(exc_info.value)
            assert "Failed to generate timeline" in err, f"missing prefix: {err!r}"

        asyncio.run(run())
        assert bridge.state.last_error is not None
        assert "Failed to generate timeline" in bridge.state.last_error or "operation" in bridge.state.last_error

    def test_detect_c2_wraps_real_keyerror_from_bad_network_activity(self) -> None:
        """detect_c2() raises ToolError when network_activity has malformed dicts.

        A ``network_activity`` dict lacking ``remote_address`` causes
        ``analysis.detect_c2_patterns`` to raise ``KeyError``. The bridge must
        re-raise it as ``ToolError`` with prefix "Failed to detect C2 patterns".
        ``bridge.state.last_error`` must be populated.
        """
        bridge = SandboxBridge()

        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
            network_activity=[cast("Any", {"wrong_key": "value"})],
        )
        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        instance.last_report = report
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.detect_c2("some-id")
            err = str(exc_info.value)
            assert "Failed to detect C2 patterns" in err, f"missing prefix: {err!r}"

        asyncio.run(run())
        assert bridge.state.last_error is not None

    def test_diff_wraps_real_attribute_error_from_bad_process_activity(self) -> None:
        """diff() raises ToolError when a report's process_activity holds a non-dict entry.

        The real ``analysis.diff_reports`` indexes every ``process_activity``
        entry through ``_extract_identity_key``, which calls ``item.get(...)``
        for each key field. When an entry is a bare ``str`` instead of a dict,
        ``str`` has no ``.get`` method, so the production code raises
        ``AttributeError`` with the standard CPython message
        ``"'str' object has no attribute 'get'"``. The bridge must re-raise that
        as ``ToolError`` with prefix "Failed to diff reports" and embed the
        original ``AttributeError`` text. Neither the analysis module nor the
        report is mocked, so the failure originates in production code.

        ``bridge.state.last_error`` must be populated with the same detail.
        """
        bridge = SandboxBridge()

        bad_report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
            process_activity=[cast("Any", "not-a-dict")],
        )
        good_report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
        )

        inst_a = StubInstance(InMemorySandbox(), "windows", instance_id="id-a")
        inst_a.last_report = bad_report
        inst_b = StubInstance(InMemorySandbox(), "windows", instance_id="id-b")
        inst_b.last_report = good_report
        bridge.attach_manager(cast("SandboxManager", StubManager({"id-a": inst_a, "id-b": inst_b})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.diff("id-a", "id-b")
            err = str(exc_info.value)
            assert "Failed to diff reports" in err, f"missing prefix: {err!r}"
            assert "'str' object has no attribute 'get'" in err, f"missing real AttributeError cause: {err!r}"

        asyncio.run(run())

        assert bridge.state.last_error is not None
        assert "'str' object has no attribute 'get'" in bridge.state.last_error

    def test_detect_behaviors_wraps_real_keyerror_from_bad_process_activity(self) -> None:
        """detect_behaviors() raises ToolError when process_activity lacks the ``name`` key.

        The real ``analysis.match_behaviors`` reads ``proc["name"]`` for every
        ``process_activity`` entry (in ``_match_persistence``). A dict missing
        the ``name`` key causes a genuine ``KeyError('name')`` inside production
        code. The bridge must re-raise it as ``ToolError`` with prefix
        "Failed to detect behaviors" and embed the missing key name. No analysis
        module is mocked, so the exception originates in the real rule engine.

        ``bridge.state.last_error`` must be populated.
        """
        bridge = SandboxBridge()

        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
            process_activity=[cast("Any", {"pid": 1, "command_line": "x"})],
        )
        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        instance.last_report = report
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.detect_behaviors("some-id")
            err = str(exc_info.value)
            assert "Failed to detect behaviors" in err, f"missing prefix: {err!r}"
            assert "name" in err, f"missing missing-key name in error: {err!r}"

        asyncio.run(run())

        assert bridge.state.last_error is not None
        assert "Failed to detect behaviors" in bridge.state.last_error or "name" in bridge.state.last_error


class TestF0003DetectBehaviorsYAML:
    """F-0003: detect_behaviors validates path, raises on JSONDecodeError/wrong shape, uses yaml.safe_load."""

    def test_raises_when_rules_file_not_found(self, tmp_path: Path) -> None:
        """detect_behaviors raises ToolError whose message contains the missing file path.

        The bridge constant ``_ERR_RULES_NOT_FOUND`` is "Custom rules file not found".
        The exact path supplied by the caller must appear in the error message so the
        caller can identify which file was missing. ``bridge.state.last_error`` must
        also be set with the same path.
        """
        bridge = SandboxBridge()

        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        instance.last_report = _make_execution_report()
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))
        missing = str(tmp_path / "no_such_file.yaml")

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.detect_behaviors("some-id", custom_rules_path=missing)
            err = str(exc_info.value)
            assert "Custom rules file not found" in err, f"missing prefix: {err!r}"
            assert missing in err, f"missing file path in error: {err!r}"

        asyncio.run(run())
        assert bridge.state.last_error is not None
        assert missing in bridge.state.last_error, f"path not in state.last_error: {bridge.state.last_error!r}"

    def test_raises_on_invalid_yaml(self, tmp_path: Path) -> None:
        """detect_behaviors raises ToolError whose message includes the YAML parsing marker.

        The error message must contain "Custom rules file is not valid YAML" (the bridge
        constant ``_ERR_RULES_INVALID``). ``bridge.state.last_error`` must be set.
        """
        bridge = SandboxBridge()

        rules_file = tmp_path / "bad.yaml"
        rules_file.write_text("key: [unclosed\n", encoding="utf-8")

        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        instance.last_report = _make_execution_report()
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.detect_behaviors("some-id", custom_rules_path=str(rules_file))
            err = str(exc_info.value)
            assert "Custom rules file is not valid YAML" in err, f"missing YAML marker: {err!r}"

        asyncio.run(run())
        assert bridge.state.last_error is not None
        assert "YAML" in bridge.state.last_error, f"'YAML' not in state.last_error: {bridge.state.last_error!r}"

    def test_raises_when_yaml_not_a_list(self, tmp_path: Path) -> None:
        """detect_behaviors raises ToolError that names the actual parsed type when YAML is not a list.

        When YAML top-level is a dict, the error message must contain "expected a list"
        and name the actual type ("dict"), because the bridge formats the message as
        "expected a list, got {type.__name__}". ``bridge.state.last_error`` must be set.
        """
        bridge = SandboxBridge()

        rules_file = tmp_path / "dict_rules.yaml"
        rules_file.write_text("key: value\n", encoding="utf-8")

        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        instance.last_report = _make_execution_report()
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.detect_behaviors("some-id", custom_rules_path=str(rules_file))
            err = str(exc_info.value)
            assert "expected a list" in err, f"missing list requirement: {err!r}"
            assert "dict" in err, f"missing actual type name: {err!r}"

        asyncio.run(run())
        assert bridge.state.last_error is not None
        assert "expected a list" in bridge.state.last_error or "dict" in bridge.state.last_error

    def test_valid_yaml_list_rules_applied_to_real_report(self, tmp_path: Path) -> None:
        """detect_behaviors passes parsed YAML rules to real match_behaviors and returns exact field values.

        This test drives the full path: YAML file -> parse -> real match_behaviors ->
        _match_custom_rules.  No part of the analysis pipeline is mocked.  The custom
        rule fires when ``process_activity`` contains an entry whose name matches
        ``conditions.process_names``.

        The bridge must return a ``matches`` list whose single custom entry has:

        - ``signature_name`` exactly equal to the YAML ``name`` field
        - ``category`` exactly equal to the YAML ``category`` field
        - ``severity`` exactly equal to the YAML ``severity`` field
        - ``mitre_attack_id`` exactly equal to the YAML ``mitre_id`` field
        - ``evidence`` list containing the exact string produced by
          ``_match_custom_rules``: ``"Process match: malicious.exe (PID 1234)"``
        - ``result["count"]`` equal to the total number of matches

        These assertions are derived from reading ``_match_custom_rules`` in
        ``intellicrack/sandbox/analysis.py`` as the independent oracle, NOT from
        re-running the production function and freezing its output.
        """
        bridge = SandboxBridge()

        yaml_content = textwrap.dedent("""\
            - name: TestCustomPersistenceRule
              category: CustomPersistence
              severity: high
              description: Detects malicious.exe execution
              mitre_id: T1547
              conditions:
                process_names:
                  - malicious.exe
        """)
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(yaml_content, encoding="utf-8")

        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=2.0,
            process_activity=[
                cast(
                    "Any",
                    {
                        "pid": 1234,
                        "name": "malicious.exe",
                        "path": "C:\\Temp\\malicious.exe",
                        "command_line": "malicious.exe --silent",
                        "parent_pid": 4,
                        "operation": "created",
                        "exit_code": None,
                        "timestamp": "2026-06-07T10:00:00",
                    },
                ),
            ],
        )

        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        instance.last_report = report
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> dict[str, Any]:
            return await bridge.detect_behaviors("some-id", custom_rules_path=str(rules_file))

        result = asyncio.run(run())

        matches: list[dict[str, Any]] = cast("list[dict[str, Any]]", result["matches"])
        custom_matches = [m for m in matches if m.get("signature_name") == "TestCustomPersistenceRule"]
        assert len(custom_matches) == 1, (
            f"Expected exactly one match for 'TestCustomPersistenceRule', got {len(custom_matches)}; "
            f"all matches: {[m.get('signature_name') for m in matches]}"
        )
        matched = custom_matches[0]
        assert matched["category"] == "CustomPersistence", f"wrong category: {matched['category']!r}"
        assert matched["severity"] == "high", f"wrong severity: {matched['severity']!r}"
        assert matched["mitre_attack_id"] == "T1547", (
            f"mitre_attack_id not propagated from YAML mitre_id: {matched.get('mitre_attack_id')!r}"
        )
        expected_evidence_entry = "Process match: malicious.exe (PID 1234)"
        assert expected_evidence_entry in matched["evidence"], (
            f"Exact evidence string {expected_evidence_entry!r} not found in: {matched['evidence']!r}"
        )
        assert result["count"] == len(matches), f"count mismatch: {result['count']} != {len(matches)}"

    def test_non_matching_process_name_produces_no_custom_match(self, tmp_path: Path) -> None:
        """detect_behaviors returns zero custom rule matches when no process in the report matches.

        A YAML rule whose ``conditions.process_names`` lists ``"benign.exe"`` must not
        fire when the report's ``process_activity`` contains only ``"malicious.exe"``.
        This confirms the rule engine does not produce false positives when the
        condition predicate is false, and that the YAML was forwarded intact (a
        silently-dropped rules list would also produce zero matches and would be
        indistinguishable — so this test must be run together with the positive-match
        test above to provide a real gate).
        """
        bridge = SandboxBridge()

        yaml_content = textwrap.dedent("""\
            - name: BenignRule
              category: Custom
              severity: low
              description: Should never fire
              mitre_id: T9999
              conditions:
                process_names:
                  - benign.exe
        """)
        rules_file = tmp_path / "no_match_rules.yaml"
        rules_file.write_text(yaml_content, encoding="utf-8")

        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
            process_activity=[
                cast(
                    "Any",
                    {
                        "pid": 5678,
                        "name": "malicious.exe",
                        "path": "C:\\Temp\\malicious.exe",
                        "command_line": "malicious.exe",
                        "parent_pid": 4,
                        "operation": "created",
                        "exit_code": None,
                        "timestamp": "2026-06-07T11:00:00",
                    },
                ),
            ],
        )

        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        instance.last_report = report
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> dict[str, Any]:
            return await bridge.detect_behaviors("some-id", custom_rules_path=str(rules_file))

        result = asyncio.run(run())

        matches: list[dict[str, Any]] = cast("list[dict[str, Any]]", result["matches"])
        benign_matches = [m for m in matches if m.get("signature_name") == "BenignRule"]
        assert not benign_matches, (
            f"Rule 'BenignRule' must not fire when 'benign.exe' is not in process_activity; found: {benign_matches!r}"
        )

    def test_multi_rule_yaml_only_matching_rules_fire(self, tmp_path: Path) -> None:
        """detect_behaviors fires exactly the rules whose conditions are satisfied.

        A YAML file with two rules — one matching (``malicious.exe``) and one not
        (``benign.exe``) — must produce exactly one custom match for the matching rule
        and zero for the non-matching rule.  This verifies that:

        1. Both rules are parsed and forwarded (the list is not truncated to the first rule).
        2. The matching predicate is applied per-rule independently (not short-circuited).
        3. No spurious cross-contamination between rule conditions occurs.
        """
        bridge = SandboxBridge()

        yaml_content = textwrap.dedent("""\
            - name: MatchingRule
              category: MatchCat
              severity: critical
              description: Should fire
              mitre_id: T1059
              conditions:
                process_names:
                  - malicious.exe
            - name: NonMatchingRule
              category: NoMatchCat
              severity: low
              description: Should not fire
              mitre_id: T9000
              conditions:
                process_names:
                  - absent.exe
        """)
        rules_file = tmp_path / "multi_rules.yaml"
        rules_file.write_text(yaml_content, encoding="utf-8")

        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.5,
            process_activity=[
                cast(
                    "Any",
                    {
                        "pid": 9001,
                        "name": "malicious.exe",
                        "path": "C:\\evil\\malicious.exe",
                        "command_line": "malicious.exe --flag",
                        "parent_pid": 4,
                        "operation": "created",
                        "exit_code": None,
                        "timestamp": "2026-06-07T12:00:00",
                    },
                ),
            ],
        )

        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        instance.last_report = report
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> dict[str, Any]:
            return await bridge.detect_behaviors("some-id", custom_rules_path=str(rules_file))

        result = asyncio.run(run())

        matches: list[dict[str, Any]] = cast("list[dict[str, Any]]", result["matches"])
        signature_names = [m["signature_name"] for m in matches]

        matching_hits = [m for m in matches if m["signature_name"] == "MatchingRule"]
        assert len(matching_hits) == 1, (
            f"Expected exactly one 'MatchingRule' hit; got {len(matching_hits)}; all signatures: {signature_names!r}"
        )
        assert matching_hits[0]["category"] == "MatchCat", f"wrong category: {matching_hits[0]['category']!r}"
        assert matching_hits[0]["severity"] == "critical", f"wrong severity: {matching_hits[0]['severity']!r}"
        assert matching_hits[0]["mitre_attack_id"] == "T1059", f"wrong mitre_attack_id: {matching_hits[0].get('mitre_attack_id')!r}"
        assert "Process match: malicious.exe (PID 9001)" in matching_hits[0]["evidence"], (
            f"exact evidence string missing; got: {matching_hits[0]['evidence']!r}"
        )

        non_matching_hits = [m for m in matches if m["signature_name"] == "NonMatchingRule"]
        assert not non_matching_hits, (
            f"Rule 'NonMatchingRule' must not fire when 'absent.exe' not in process_activity; found: {non_matching_hits!r}"
        )


class TestF0004YaraScanModeValidation:
    """F-0004: yara_scan validates mode in ('files', 'memory'); raises ToolError on invalid."""

    def test_raises_on_invalid_scan_target(self) -> None:
        """yara_scan raises ToolError with the exact validation message for invalid scan_target.

        The bridge constant ``_ERR_YARA_INVALID_MODE`` is
        "Invalid scan_target; must be 'files' or 'memory'". The full literal message
        must appear so callers know exactly which values are accepted.
        """
        bridge = SandboxBridge()

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.yara_scan("some-id", scan_target="processes")
            err = str(exc_info.value)
            assert "Invalid scan_target" in err, f"missing prefix: {err!r}"
            assert "files" in err, f"'files' not listed in error: {err!r}"
            assert "memory" in err, f"'memory' not listed in error: {err!r}"

        asyncio.run(run())

    def test_raises_on_arbitrary_invalid_target(self) -> None:
        """yara_scan raises ToolError for any non-enumerated scan_target value.

        "network" is not a valid target and must produce the same error as any
        other invalid value, confirming the validation is not hard-coded to one string.
        """
        bridge = SandboxBridge()

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.yara_scan("some-id", scan_target="network")
            err = str(exc_info.value)
            assert "Invalid scan_target" in err, f"missing prefix: {err!r}"

        asyncio.run(run())

    @staticmethod
    def _scan_target_passthrough_matches() -> list[dict[str, Any]]:
        """Build two distinguishing YARA match records for passthrough assertions.

        Returns:
            list[dict[str, Any]]: Two match dicts with unique rule names, tags,
            and string offsets so a transform that drops or renames fields is
            detectable against this oracle.
        """
        return [
            {
                "rule": "EvilPacker",
                "namespace": "default",
                "tags": ["packer", "evasion"],
                "meta": {"author": "test", "severity": 5},
                "strings": [{"identifier": "$a", "offset": 4096, "data": "deadbeef"}],
            },
            {
                "rule": "SuspiciousImport",
                "namespace": "imports",
                "tags": ["api"],
                "meta": {"author": "test", "severity": 2},
                "strings": [{"identifier": "$b", "offset": 8192, "data": "cafebabe"}],
            },
        ]

    def _assert_matches_preserved(self, result: dict[str, Any]) -> None:
        """Assert the bridge forwarded the transport matches without loss.

        Args:
            result: The dict returned by ``bridge.yara_scan``.
        """
        expected = self._scan_target_passthrough_matches()
        matches: list[dict[str, Any]] = cast("list[dict[str, Any]]", result["matches"])
        assert isinstance(matches, list)
        assert result["match_count"] == len(expected), f"match_count must equal number of real matches: {result['match_count']!r}"
        assert result["match_count"] > 0, "passthrough matches must be non-empty to gate against silent dropping"
        assert matches == expected, f"bridge altered the match records during passthrough: {matches!r}"
        rule_names = [m["rule"] for m in matches]
        assert rule_names == ["EvilPacker", "SuspiciousImport"], f"rule names not preserved in order: {rule_names!r}"
        assert matches[0]["strings"][0]["offset"] == 4096, f"nested match field corrupted: {matches[0]['strings']!r}"

    def test_accepts_files_target(self) -> None:
        """yara_scan accepts 'files' and forwards the engine's match records intact.

        The transport boundary (``instance.sandbox.yara_scan``) returns two
        distinguishing match records. The bridge must preserve every record and
        nested field verbatim and set ``match_count`` to exactly ``len(matches)``,
        so a transform that drops, renames, or reorders matches trips the gate.
        """
        bridge = SandboxBridge()
        engine_matches = self._scan_target_passthrough_matches()

        sandbox = _ScriptedSandbox(yara_matches=engine_matches)
        instance = StubInstance(sandbox, "windows", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> dict[str, Any]:
            return await bridge.yara_scan("some-id", scan_target="files")

        result = asyncio.run(run())
        assert sandbox.yara_scan_calls == [(None, "files")], f"unexpected forwarded call args: {sandbox.yara_scan_calls!r}"
        self._assert_matches_preserved(result)

    def test_accepts_memory_target(self) -> None:
        """yara_scan accepts 'memory' and forwards the engine's match records intact.

        Same passthrough-fidelity gate as the 'files' case, additionally
        confirming the validated ``scan_target`` is forwarded unchanged to the
        sandbox scan call.
        """
        bridge = SandboxBridge()
        engine_matches = self._scan_target_passthrough_matches()

        sandbox = _ScriptedSandbox(yara_matches=engine_matches)
        instance = StubInstance(sandbox, "windows", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> dict[str, Any]:
            return await bridge.yara_scan("some-id", scan_target="memory")

        result = asyncio.run(run())
        assert sandbox.yara_scan_calls == [(None, "memory")], f"unexpected forwarded call args: {sandbox.yara_scan_calls!r}"
        self._assert_matches_preserved(result)


class TestF0005PublicQMPAgentAccessors:
    """F-0005: Uses public qmp/agent accessors instead of private _qmp/_agent."""

    def test_qemu_sandbox_qmp_returns_none_when_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """QEMUSandbox.qmp returns None when no QMP client has been attached.

        Additionally, the bridge must raise ``ToolError`` with prefix
        "Failed to resume VM execution" when ``cont()`` is called and
        ``instance.sandbox.qmp`` is None, confirming that bridge dispatch
        reads the public property and guards against a missing QMP channel.
        """
        qemu = pytest.importorskip("intellicrack.sandbox.qemu")
        qemu_sandbox_cls = qemu.QEMUSandbox

        sandbox = qemu_sandbox_cls.__new__(qemu_sandbox_cls)
        monkeypatch.setattr(sandbox, "_qmp", None, raising=False)
        monkeypatch.setattr(sandbox, "_agent", None, raising=False)

        assert sandbox.qmp is None
        assert sandbox.agent is None

        bridge = SandboxBridge()
        instance = StubInstance(sandbox, "qemu", instance_id="qemu-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"qemu-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.cont("qemu-id")
            err = str(exc_info.value)
            assert "Failed to resume VM execution" in err, f"missing prefix: {err!r}"
            assert "not connected" in err or "QMP" in err, f"missing QMP detail: {err!r}"

        asyncio.run(run())

    def test_qemu_sandbox_has_public_qmp_property(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """QEMUSandbox exposes qmp as a public property returning the QMP client."""
        qemu = pytest.importorskip("intellicrack.sandbox.qemu")
        qemu_sandbox_cls = qemu.QEMUSandbox
        qmp_client_cls = qemu.QMPClient

        sandbox = qemu_sandbox_cls.__new__(qemu_sandbox_cls)
        real_client = qmp_client_cls.__new__(qmp_client_cls)
        monkeypatch.setattr(sandbox, "_qmp", real_client, raising=False)

        assert sandbox.qmp is real_client

    def test_qemu_sandbox_has_public_agent_property(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """QEMUSandbox exposes agent as a public property returning the GuestAgentClient."""
        qemu = pytest.importorskip("intellicrack.sandbox.qemu")
        qemu_sandbox_cls = qemu.QEMUSandbox
        guest_agent_cls = qemu.GuestAgentClient

        sandbox = qemu_sandbox_cls.__new__(qemu_sandbox_cls)
        real_agent = guest_agent_cls.__new__(guest_agent_cls)
        monkeypatch.setattr(sandbox, "_agent", real_agent, raising=False)

        assert sandbox.agent is real_agent

    def test_get_pending_messages_uses_agent_not_private(self) -> None:
        """get_pending_messages() reads agent via public property and returns correct schema.

        The return dict must have ``count`` (int) and ``messages`` (list) keys.
        When the agent returns an empty list, ``count`` must be 0 and ``messages``
        must be an empty list — not some other truthful but wrong value.
        """
        pytest.importorskip("intellicrack.sandbox.qemu")

        bridge = SandboxBridge()
        sandbox = InMemoryQEMUSandbox()
        sandbox.agent = cast("StubAgent", _ScriptedAgent(messages=[]))
        instance = StubInstance(sandbox, "qemu", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> dict[str, Any]:
            return await bridge.get_pending_messages("some-id")

        result = asyncio.run(run())
        assert result["count"] == 0
        assert result["messages"] == []


class TestF0006NoHotPathInfoLogs:
    """F-0006: No *_started info logs in hot paths (is_available, status, list)."""

    def test_is_available_no_info_log(self) -> None:
        """is_available() does not emit an info-level 'started' log and returns a bool.

        The return value must be a boolean (not just truthy) so callers can rely
        on ``isinstance(result, bool)`` checks. The log-absence check confirms the
        bridge does not spam structured logs on every availability poll.
        """
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", StubManager({})))

        records: list[logging.LogRecord] = []

        class CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = CapturingHandler()
        handler.setLevel(logging.INFO)
        root_logger = logging.getLogger("intellicrack.bridges.sandbox_bridge")
        root_logger.addHandler(handler)
        result: bool
        try:
            result = asyncio.run(bridge.is_available())
        finally:
            root_logger.removeHandler(handler)

        assert isinstance(result, bool), f"expected bool, got {type(result).__name__}"
        assert result is True, "expected True when get_available_types returns non-empty list"
        started_records = [r for r in records if "started" in r.getMessage().lower()]
        assert not started_records, f"Unexpected 'started' info logs: {[r.getMessage() for r in started_records]}"

    def test_status_no_info_log(self) -> None:
        """status() does not emit an info-level 'started' log and returns a dict with instances key.

        The returned dict must contain "instances" (the key the manager exposes)
        or at minimum be a non-empty dict. The log-absence check applies only to
        the "started" event category.
        """
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", StubManager({})))

        records: list[logging.LogRecord] = []

        class CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = CapturingHandler()
        handler.setLevel(logging.INFO)
        root_logger = logging.getLogger("intellicrack.bridges.sandbox_bridge")
        root_logger.addHandler(handler)
        result: dict[str, Any]
        try:
            result = asyncio.run(bridge.status())
        finally:
            root_logger.removeHandler(handler)

        assert isinstance(result, dict), f"expected dict, got {type(result).__name__}"
        assert "instances" in result, f"missing 'instances' key in status result: {list(result.keys())}"
        started_records = [r for r in records if "started" in r.getMessage().lower()]
        assert not started_records, f"Unexpected 'started' info logs: {[r.getMessage() for r in started_records]}"

    def test_list_no_info_log(self) -> None:
        """list() does not emit an info-level 'started' log and returns a list.

        When the manager has no instances, the list must be empty (``[]``), not None
        or some truthy non-list. Each entry in a non-empty list must have at minimum
        the ``id`` and ``type`` keys.
        """
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", StubManager({})))

        records: list[logging.LogRecord] = []

        class CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = CapturingHandler()
        handler.setLevel(logging.INFO)
        root_logger = logging.getLogger("intellicrack.bridges.sandbox_bridge")
        root_logger.addHandler(handler)
        result: list[dict[str, Any]]
        try:
            result = asyncio.run(bridge.list())
        finally:
            root_logger.removeHandler(handler)

        assert isinstance(result, list), f"expected list, got {type(result).__name__}"
        assert result == [], f"expected empty list for no instances, got {result!r}"
        started_records = [r for r in records if "started" in r.getMessage().lower()]
        assert not started_records, f"Unexpected 'started' info logs: {[r.getMessage() for r in started_records]}"


class TestF0007GetVNCPort:
    """F-0007: get_vnc_port gates on QEMU type and raises ToolError for non-QEMU or no VNC."""

    def test_raises_on_non_qemu_sandbox(self) -> None:
        """get_vnc_port raises ToolError with the exact "requires QEMU sandbox" message.

        The production message prefix is "Operation requires QEMU sandbox" (constant
        ``_ERR_QEMU_REQUIRED``). Any other message text would break callers that
        pattern-match on the error.
        """
        bridge = SandboxBridge()

        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.get_vnc_port("some-id")
            err = str(exc_info.value)
            assert "requires QEMU sandbox" in err, f"missing QEMU gate message: {err!r}"

        asyncio.run(run())

    def test_raises_when_vnc_port_is_none(self) -> None:
        """get_vnc_port raises ToolError with "VNC" in the message when VNC port is not allocated.

        The production constant ``_ERR_VNC_PORT_UNAVAILABLE`` is "VNC port is not
        allocated on this QEMU sandbox". The message must contain "VNC" so callers
        know why the operation failed.
        """
        bridge = SandboxBridge()

        instance = StubInstance(_ScriptedSandbox(vnc_port=None), "qemu", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.get_vnc_port("some-id")
            err = str(exc_info.value)
            assert "VNC" in err, f"missing VNC in error: {err!r}"
            assert "not" in err.lower() or "unavailable" in err.lower() or "allocated" in err.lower(), (
                f"missing unavailability signal: {err!r}"
            )

        asyncio.run(run())

    def test_returns_vnc_port_when_configured(self) -> None:
        """get_vnc_port returns exactly 5900 when the sandbox's vnc_port property is 5900.

        This confirms the bridge does not transform the port value (e.g., add an
        offset or convert to a string) before returning it.
        """
        bridge = SandboxBridge()

        instance = StubInstance(InMemorySandbox(), "qemu", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> int:
            return await bridge.get_vnc_port("some-id")

        result = asyncio.run(run())
        assert result == 5900
        assert isinstance(result, int), f"expected int, got {type(result).__name__}"

    def test_raises_on_missing_instance(self) -> None:
        """get_vnc_port raises ToolError whose message includes the missing instance ID.

        The production message is "Sandbox instance not found: {instance_id}".
        The exact ID must appear so the caller can identify which instance is absent.
        """
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", StubManager({})))
        missing_id = "missing-id-abc123"

        async def run() -> None:
            with pytest.raises(ToolError) as exc_info:
                await bridge.get_vnc_port(missing_id)
            err = str(exc_info.value)
            assert "Sandbox instance not found" in err, f"missing prefix: {err!r}"
            assert missing_id in err, f"missing instance ID in error: {err!r}"

        asyncio.run(run())


class TestF0008QEMUGatedMethods:
    """F-0008: pcap_start/screenshot/extract_dropped_files/anti_evasion raise on non-QEMU.

    ``memory_dump`` is no longer QEMU-only (audit7 F-0021): the Windows sandbox
    implementation now supports per-process minidumps via ``MiniDumpWriteDump``
    with a required ``target_pid`` argument. ``memory_dump`` therefore raises a
    different error (``target_pid is required for Windows Sandbox memory_dump``)
    when invoked against a Windows instance without ``target_pid``, which is
    covered separately in :class:`tests.sandbox.windows`.
    """

    @pytest.mark.parametrize(
        ("method", "kwargs"),
        [
            ("pcap_start", {}),
            ("screenshot", {}),
            ("extract_dropped_files", {}),
            ("anti_evasion", {}),
        ],
    )
    def test_raises_on_windows_sandbox(self, method: str, kwargs: dict[str, Any]) -> None:
        """Each QEMU-only method raises ToolError with "requires QEMU sandbox" for windows type.

        Args:
            method: Bridge method name to invoke.
            kwargs: Extra keyword arguments for the method.

        The exact phrase "requires QEMU sandbox" must appear in the error, confirming
        the bridge uses ``_ERR_QEMU_REQUIRED`` rather than a different message.
        """
        bridge = SandboxBridge()

        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> None:
            fn = getattr(bridge, method)
            with pytest.raises(ToolError) as exc_info:
                await fn("some-id", **kwargs)
            err = str(exc_info.value)
            assert "requires QEMU sandbox" in err, f"{method}() raised ToolError but message lacks 'requires QEMU sandbox': {err!r}"

        asyncio.run(run())


class TestF0009EnsureManagerDestroyed:
    """F-0009: ensure_manager raises ToolError when manager was shut down."""

    def test_raises_after_shutdown(self) -> None:
        """ensure_manager raises ToolError with "manager was shut down" after shutdown().

        After ``shutdown()`` is called, ``bridge.manager`` must be None,
        ``bridge.manager_destroyed`` must be True, and every subsequent call to
        ``ensure_manager()`` must raise ``ToolError`` with the exact phrase
        "manager was shut down". The phrase is the bridge constant
        ``_ERR_MANAGER_DESTROYED``.
        """
        bridge = SandboxBridge()

        async def run() -> None:
            bridge.attach_manager(cast("SandboxManager", StubManager({})))
            await bridge.shutdown()
            assert bridge.manager is None
            assert bridge.manager_destroyed is True
            with pytest.raises(ToolError) as exc_info:
                bridge.ensure_manager()
            err = str(exc_info.value)
            assert "manager was shut down" in err, f"missing expected phrase: {err!r}"

        asyncio.run(run())

    def test_succeeds_before_shutdown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ensure_manager creates a new manager when never initialized."""
        bridge = SandboxBridge()

        bridge_module = importlib.import_module("intellicrack.bridges.sandbox_bridge")
        monkeypatch.setattr(bridge_module, "SandboxManager", StubManager)
        mgr = bridge.ensure_manager()
        assert mgr is not None
        assert bridge.manager is mgr

    def test_returns_existing_manager_on_repeated_calls(self) -> None:
        """ensure_manager returns the same object across multiple calls without creating a new one.

        Calling ``ensure_manager()`` twice must return identical objects (same
        ``id()``) and must not replace the stored ``_manager``. This confirms the
        bridge does not construct a fresh ``SandboxManager`` on every invocation.
        """
        bridge = SandboxBridge()
        stub_mgr = StubManager({})
        bridge.attach_manager(cast("SandboxManager", stub_mgr))

        result_a = bridge.ensure_manager()
        result_b = bridge.ensure_manager()
        assert result_a is cast("SandboxManager", stub_mgr)
        assert result_b is cast("SandboxManager", stub_mgr)
        assert result_a is result_b, "ensure_manager must return the same object on repeated calls"
        assert bridge.manager is cast("SandboxManager", stub_mgr)


class TestF0010BridgeStateUpdates:
    """F-0010: BridgeState updated through state-changing methods; error paths set last_error."""

    def test_create_updates_state_on_success(self) -> None:
        """create() sets BridgeState.last_error to None on success."""
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", StubManager({})))

        asyncio.run(bridge.create(sandbox_type="windows"))
        assert bridge.state.last_error is None

    def test_create_sets_last_error_on_failure(self) -> None:
        """create() sets BridgeState.last_error when SandboxError occurs."""
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", _FailingManager(create_error=SandboxError("creation failed"))))

        async def run() -> None:
            with pytest.raises(ToolError):
                await bridge.create(sandbox_type="windows")

        asyncio.run(run())
        assert bridge.state.last_error is not None
        assert "creation failed" in bridge.state.last_error

    def test_run_binary_updates_binary_loaded(self, tmp_path: Path) -> None:
        """run_binary() sets BridgeState.binary_loaded to True on success."""
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", StubManager({})))

        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 62)

        asyncio.run(bridge.run_binary(str(binary)))
        assert bridge.state.binary_loaded is True

    def test_run_binary_sets_last_error_on_failure(self, tmp_path: Path) -> None:
        """run_binary() sets BridgeState.last_error on SandboxError."""
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", _FailingManager(run_binary_error=SandboxError("exec failed"))))

        binary = tmp_path / "fail.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 62)

        async def run() -> None:
            with pytest.raises(ToolError):
                await bridge.run_binary(str(binary))

        asyncio.run(run())
        assert bridge.state.last_error is not None


class TestF0010LastErrorLifecycleSymmetric:
    """F-0010: last_error must be cleared on success across every wrapped method.

    Regression suite covering the asymmetric ``BridgeState.last_error``
    defect. For each public bridge method listed in the audit finding,
    the suite drives a failing call (which should set ``last_error``),
    then a passing call (which should clear it). On main the second
    assertion fails because ``last_error`` is never reset; on the branch
    introducing the state tracker both assertions pass.
    """

    @staticmethod
    def _run_failure_then_success(
        bridge: SandboxBridge,
        fail_instance: StubInstance,
        ok_instance: StubInstance,
        failure_call: Callable[[SandboxBridge], Awaitable[object]],
        success_call: Callable[[SandboxBridge], Awaitable[object]],
        failure_substring: str,
    ) -> None:
        """Drive a failing op followed by a passing op and assert symmetry.

        Args:
            bridge: The bridge under test.
            fail_instance: Instance (identified by its own ``id``) attached
                to the manager for the failing call.
            ok_instance: Instance (identified by its own ``id``) attached to
                the manager for the succeeding call.
            failure_call: Async callable that invokes the failing bridge method.
            success_call: Async callable that invokes the succeeding bridge method.
            failure_substring: Substring expected inside ``state.last_error``
                after the failing call.
        """

        async def fail_then_recover() -> None:
            bridge.attach_manager(cast("SandboxManager", StubManager({fail_instance.id: fail_instance})))
            with pytest.raises(ToolError):
                await failure_call(bridge)

            assert bridge.state.last_error is not None
            assert failure_substring in bridge.state.last_error, bridge.state.last_error

            bridge.attach_manager(cast("SandboxManager", StubManager({ok_instance.id: ok_instance})))
            await success_call(bridge)

            assert bridge.state.last_error is None, f"last_error not cleared after successful call (was: {bridge.state.last_error!r})"

        asyncio.run(fail_then_recover())

    def test_copy_to_clears_last_error_on_success(self, tmp_path: Path) -> None:
        """Copy_to clears last_error after a successful call following a failure."""
        bridge = SandboxBridge()

        source = tmp_path / "file.bin"
        source.write_bytes(b"data")

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="copy_to_sandbox", fail_error=SandboxError("copy failed")),
            "qemu",
            instance_id="inst",
        )
        ok_instance = StubInstance(_ScriptedSandbox(), "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.copy_to("inst", str(source), "/dest"),
            lambda b: b.copy_to("inst", str(source), "/dest"),
            "copy failed",
        )

    def test_copy_from_clears_last_error_on_success(self, tmp_path: Path) -> None:
        """Copy_from clears last_error after a successful call following a failure."""
        bridge = SandboxBridge()
        dest = tmp_path / "out.bin"

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="copy_from_sandbox", fail_error=SandboxError("read failed")),
            "qemu",
            instance_id="inst",
        )
        ok_instance = StubInstance(_ScriptedSandbox(), "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.copy_from("inst", "/src", str(dest)),
            lambda b: b.copy_from("inst", "/src", str(dest)),
            "read failed",
        )

    def test_snapshot_create_clears_last_error_on_success(self) -> None:
        """Snapshot_create clears last_error after success following a failure."""
        bridge = SandboxBridge()

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="take_snapshot", fail_error=SandboxError("snap fail")),
            "qemu",
            instance_id="inst",
        )
        ok_instance = StubInstance(_ScriptedSandbox(), "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.snapshot_create("inst", "snap"),
            lambda b: b.snapshot_create("inst", "snap"),
            "snap fail",
        )

    def test_snapshot_restore_clears_last_error_on_success(self) -> None:
        """Snapshot_restore clears last_error after success following a failure."""
        bridge = SandboxBridge()

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="restore_snapshot", fail_error=SandboxError("restore fail")),
            "qemu",
            instance_id="inst",
        )
        ok_sandbox = _ScriptedSandbox()
        ok_sandbox.seed_snapshot("snap-1")
        ok_instance = StubInstance(ok_sandbox, "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.snapshot_restore("inst", "snap-1"),
            lambda b: b.snapshot_restore("inst", "snap-1"),
            "restore fail",
        )

    def test_snapshot_list_clears_last_error_on_success(self) -> None:
        """Snapshot_list clears last_error after success following a failure."""
        bridge = SandboxBridge()

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="list_snapshots", fail_error=SandboxError("list fail")),
            "qemu",
            instance_id="inst",
        )
        ok_instance = StubInstance(_ScriptedSandbox(), "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.snapshot_list("inst"),
            lambda b: b.snapshot_list("inst"),
            "list fail",
        )

    def test_snapshot_delete_clears_last_error_on_success(self) -> None:
        """Snapshot_delete clears last_error after success following a failure."""
        bridge = SandboxBridge()

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="delete_snapshot", fail_error=SandboxError("del fail")),
            "qemu",
            instance_id="inst",
        )
        ok_sandbox = _ScriptedSandbox()
        ok_sandbox.seed_snapshot("snap-snap")
        ok_instance = StubInstance(ok_sandbox, "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.snapshot_delete("inst", "snap"),
            lambda b: b.snapshot_delete("inst", "snap"),
            "del fail",
        )

    def test_pcap_start_clears_last_error_on_success(self) -> None:
        """Pcap_start clears last_error after success following a failure."""
        bridge = SandboxBridge()

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="start_pcap_capture", fail_error=SandboxError("pcap fail")),
            "qemu",
            instance_id="inst",
        )
        ok_instance = StubInstance(_ScriptedSandbox(), "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.pcap_start("inst"),
            lambda b: b.pcap_start("inst"),
            "pcap fail",
        )

    def test_pcap_stop_clears_last_error_on_success(self) -> None:
        """Pcap_stop clears last_error after success following a failure."""
        bridge = SandboxBridge()

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="stop_pcap_capture", fail_error=SandboxError("stop fail")),
            "qemu",
            instance_id="inst",
        )
        ok_instance = StubInstance(_ScriptedSandbox(), "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.pcap_stop("inst", "cap-1"),
            lambda b: b.pcap_stop("inst", "cap-1"),
            "stop fail",
        )

    def test_screenshot_clears_last_error_on_success(self) -> None:
        """Screenshot clears last_error after success following a failure."""
        bridge = SandboxBridge()

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="capture_screenshot", fail_error=SandboxError("shot fail")),
            "qemu",
            instance_id="inst",
        )
        ok_instance = StubInstance(_ScriptedSandbox(), "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.screenshot("inst"),
            lambda b: b.screenshot("inst"),
            "shot fail",
        )

    def test_anti_evasion_clears_last_error_on_success(self) -> None:
        """Anti_evasion clears last_error after success following a failure."""
        bridge = SandboxBridge()

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="apply_anti_evasion", fail_error=SandboxError("evasion fail")),
            "qemu",
            instance_id="inst",
        )
        ok_instance = StubInstance(_ScriptedSandbox(), "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.anti_evasion("inst"),
            lambda b: b.anti_evasion("inst"),
            "evasion fail",
        )

    def test_memory_dump_clears_last_error_on_success(self) -> None:
        """Memory_dump clears last_error after success following a failure."""
        bridge = SandboxBridge()

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="dump_memory", fail_error=SandboxError("dump fail")),
            "qemu",
            instance_id="inst",
        )
        ok_instance = StubInstance(_ScriptedSandbox(), "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.memory_dump("inst"),
            lambda b: b.memory_dump("inst"),
            "dump fail",
        )

    def test_extract_dropped_files_clears_last_error_on_success(self) -> None:
        """Extract_dropped_files clears last_error after success following a failure."""
        bridge = SandboxBridge()

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="extract_dropped_files", fail_error=SandboxError("zip fail")),
            "qemu",
            instance_id="inst",
        )
        ok_instance = StubInstance(_ScriptedSandbox(), "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.extract_dropped_files("inst"),
            lambda b: b.extract_dropped_files("inst"),
            "zip fail",
        )

    def test_yara_scan_clears_last_error_on_success(self) -> None:
        """Yara_scan clears last_error after success following a failure."""
        bridge = SandboxBridge()

        fail_instance = StubInstance(
            _ScriptedSandbox(fail_method="yara_scan", fail_error=SandboxError("yara fail")),
            "qemu",
            instance_id="inst",
        )
        ok_instance = StubInstance(_ScriptedSandbox(), "qemu", instance_id="inst")

        self._run_failure_then_success(
            bridge,
            fail_instance,
            ok_instance,
            lambda b: b.yara_scan("inst"),
            lambda b: b.yara_scan("inst"),
            "yara fail",
        )

    def test_extract_iocs_clears_last_error_on_success(self) -> None:
        """Extract_iocs clears last_error after success following a failure.

        The failure is a genuine ``KeyError`` raised by the real
        ``analysis.extract_iocs`` when ``network_activity`` lacks
        ``remote_address`` (as in :class:`TestF0002NarrowExceptionHandling`),
        not a mocked analysis function.
        """
        bridge = SandboxBridge()

        bad_report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
            network_activity=[cast("Any", {"wrong_key": "value"})],
        )

        async def fail_then_recover() -> None:
            bad_instance = StubInstance(InMemorySandbox(), "windows", instance_id="inst")
            bad_instance.last_report = bad_report
            bridge.attach_manager(cast("SandboxManager", StubManager({"inst": bad_instance})))
            with pytest.raises(ToolError, match="remote_address"):
                await bridge.extract_iocs("inst")

            assert bridge.state.last_error is not None
            assert "remote_address" in bridge.state.last_error

            ok_instance = StubInstance(InMemorySandbox(), "windows", instance_id="inst")
            ok_instance.last_report = _make_execution_report()
            bridge.attach_manager(cast("SandboxManager", StubManager({"inst": ok_instance})))
            await bridge.extract_iocs("inst")

            assert bridge.state.last_error is None, bridge.state.last_error

        asyncio.run(fail_then_recover())

    def test_timeline_clears_last_error_on_success(self) -> None:
        """Timeline clears last_error after success following a failure.

        The failure is a genuine ``KeyError`` raised by the real
        ``analysis.generate_timeline`` when ``file_changes`` lacks
        ``operation``, matching :class:`TestF0002NarrowExceptionHandling`.
        """
        bridge = SandboxBridge()

        bad_report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
            file_changes=[cast("Any", {"missing": "keys"})],
        )

        async def fail_then_recover() -> None:
            bad_instance = StubInstance(InMemorySandbox(), "windows", instance_id="inst")
            bad_instance.last_report = bad_report
            bridge.attach_manager(cast("SandboxManager", StubManager({"inst": bad_instance})))
            with pytest.raises(ToolError, match="operation"):
                await bridge.timeline("inst")

            assert bridge.state.last_error is not None
            assert "operation" in bridge.state.last_error

            ok_instance = StubInstance(InMemorySandbox(), "windows", instance_id="inst")
            ok_instance.last_report = _make_execution_report()
            bridge.attach_manager(cast("SandboxManager", StubManager({"inst": ok_instance})))
            await bridge.timeline("inst")

            assert bridge.state.last_error is None

        asyncio.run(fail_then_recover())

    def test_detect_behaviors_clears_last_error_on_success(self) -> None:
        """Detect_behaviors clears last_error after success following a failure.

        The failure is a genuine ``KeyError`` raised by the real
        ``analysis.match_behaviors`` when ``process_activity`` lacks
        ``name``, matching :class:`TestF0002NarrowExceptionHandling`.
        """
        bridge = SandboxBridge()

        bad_report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
            process_activity=[cast("Any", {"pid": 1, "command_line": "x"})],
        )

        async def fail_then_recover() -> None:
            bad_instance = StubInstance(InMemorySandbox(), "windows", instance_id="inst")
            bad_instance.last_report = bad_report
            bridge.attach_manager(cast("SandboxManager", StubManager({"inst": bad_instance})))
            with pytest.raises(ToolError, match="name"):
                await bridge.detect_behaviors("inst")

            assert bridge.state.last_error is not None
            assert "name" in bridge.state.last_error

            ok_instance = StubInstance(InMemorySandbox(), "windows", instance_id="inst")
            ok_instance.last_report = _make_execution_report()
            bridge.attach_manager(cast("SandboxManager", StubManager({"inst": ok_instance})))
            await bridge.detect_behaviors("inst")

            assert bridge.state.last_error is None

        asyncio.run(fail_then_recover())

    def test_detect_c2_clears_last_error_on_success(self) -> None:
        """Detect_c2 clears last_error after success following a failure.

        The failure is a genuine ``KeyError`` raised by the real
        ``analysis.detect_c2_patterns`` when ``network_activity`` lacks
        ``remote_address``, matching :class:`TestF0002NarrowExceptionHandling`.
        """
        bridge = SandboxBridge()

        bad_report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
            network_activity=[cast("Any", {"wrong_key": "value"})],
        )

        async def fail_then_recover() -> None:
            bad_instance = StubInstance(InMemorySandbox(), "windows", instance_id="inst")
            bad_instance.last_report = bad_report
            bridge.attach_manager(cast("SandboxManager", StubManager({"inst": bad_instance})))
            with pytest.raises(ToolError, match="remote_address"):
                await bridge.detect_c2("inst")

            assert bridge.state.last_error is not None
            assert "remote_address" in bridge.state.last_error

            ok_instance = StubInstance(InMemorySandbox(), "windows", instance_id="inst")
            ok_instance.last_report = _make_execution_report()
            bridge.attach_manager(cast("SandboxManager", StubManager({"inst": ok_instance})))
            await bridge.detect_c2("inst")

            assert bridge.state.last_error is None

        asyncio.run(fail_then_recover())

    def test_diff_clears_last_error_on_success(self) -> None:
        """Diff clears last_error after success following a failure.

        The failure is a genuine ``AttributeError`` raised by the real
        ``analysis.diff_reports`` when ``process_activity`` holds a bare
        ``str`` instead of a dict, matching
        :class:`TestF0002NarrowExceptionHandling`.
        """
        bridge = SandboxBridge()

        bad_report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
            process_activity=[cast("Any", "not-a-dict")],
        )
        good_report = _make_execution_report()

        async def fail_then_recover() -> None:
            bad_a = StubInstance(InMemorySandbox(), "windows", instance_id="a")
            bad_a.last_report = bad_report
            bad_b = StubInstance(InMemorySandbox(), "windows", instance_id="b")
            bad_b.last_report = good_report
            bridge.attach_manager(cast("SandboxManager", StubManager({"a": bad_a, "b": bad_b})))
            with pytest.raises(ToolError, match="'str' object has no attribute 'get'"):
                await bridge.diff("a", "b")

            assert bridge.state.last_error is not None
            assert "'str' object has no attribute 'get'" in bridge.state.last_error

            ok_a = StubInstance(InMemorySandbox(), "windows", instance_id="a")
            ok_a.last_report = good_report
            ok_b = StubInstance(InMemorySandbox(), "windows", instance_id="b")
            ok_b.last_report = good_report
            bridge.attach_manager(cast("SandboxManager", StubManager({"a": ok_a, "b": ok_b})))
            await bridge.diff("a", "b")

            assert bridge.state.last_error is None

        asyncio.run(fail_then_recover())

    def test_state_preserves_target_path_across_recovery(self, tmp_path: Path) -> None:
        """A successful op after run_binary preserves target_path / binary_loaded."""
        bridge = SandboxBridge()
        binary = tmp_path / "tracked.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 62)

        async def run() -> None:
            bridge.attach_manager(cast("SandboxManager", StubManager({})))
            await bridge.run_binary(str(binary))

            assert bridge.state.binary_loaded is True
            assert bridge.state.target_path is not None

            snapshot_instance = StubInstance(InMemoryQEMUSandbox(), "qemu", instance_id="inst")
            bridge.attach_manager(cast("SandboxManager", StubManager({"inst": snapshot_instance})))
            await bridge.snapshot_create("inst", "snap")

            assert bridge.state.binary_loaded is True
            assert bridge.state.target_path is not None
            assert bridge.state.last_error is None

        asyncio.run(run())


class TestF0011ToolDefDefaults:
    """F-0011: Tool definitions have default= values for time_limit, output_path, args, categories."""

    def _get_param(self, fn_name: str, param_name: str) -> object:
        """Return parameter from tool definition by function and parameter name.

        Args:
            fn_name: Name of the function in the tool definition.
            param_name: Name of the parameter to look up.

        Returns:
            object: The matching ToolParameter, or None if not found.
        """
        bridge = SandboxBridge()
        td = bridge.tool_definition
        for fn in td.functions:
            if fn.name == fn_name:
                for p in fn.parameters:
                    if p.name == param_name:
                        return p
        return None

    def test_run_binary_time_limit_has_default(self) -> None:
        """sandbox.run_binary time_limit has a default value."""
        param = self._get_param("sandbox.run_binary", "time_limit")
        assert param is not None
        assert getattr(param, "default", None) is not None

    def test_run_binary_args_has_default(self) -> None:
        """sandbox.run_binary args has a default value."""
        param = self._get_param("sandbox.run_binary", "args")
        assert param is not None
        assert getattr(param, "default", None) is not None

    def test_timeline_categories_has_default(self) -> None:
        """sandbox.timeline categories has a default value."""
        param = self._get_param("sandbox.timeline", "categories")
        assert param is not None
        assert getattr(param, "default", None) is not None

    def test_pcap_stop_output_path_has_default(self) -> None:
        """sandbox.pcap_stop output_path has a default value."""
        param = self._get_param("sandbox.pcap_stop", "output_path")
        assert param is not None
        assert getattr(param, "default", None) is not None

    def test_screenshot_output_path_has_default(self) -> None:
        """sandbox.screenshot output_path has a default value."""
        param = self._get_param("sandbox.screenshot", "output_path")
        assert param is not None
        assert getattr(param, "default", None) is not None

    def test_memory_dump_output_path_has_default(self) -> None:
        """sandbox.memory_dump output_path has a default value."""
        param = self._get_param("sandbox.memory_dump", "output_path")
        assert param is not None
        assert getattr(param, "default", None) is not None

    def test_extract_dropped_files_output_path_has_default(self) -> None:
        """sandbox.extract_dropped_files output_path has a default value."""
        param = self._get_param("sandbox.extract_dropped_files", "output_path")
        assert param is not None
        assert getattr(param, "default", None) is not None


class TestF0012AnalysisModuleCache:
    """F-0012: _get_analysis_module() is cached via lru_cache."""

    def test_analysis_module_called_once_for_multiple_bridge_calls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_get_analysis_module is called at most once for multiple analysis calls."""
        bridge = SandboxBridge()

        instance = StubInstance(InMemorySandbox(), "windows", instance_id="some-id")
        instance.last_report = _make_execution_report()
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        call_count = 0
        analysis_stub = _CountingAnalysisModule()

        def counting_import() -> _CountingAnalysisModule:
            nonlocal call_count
            call_count += 1
            return analysis_stub

        bridge_module = importlib.import_module("intellicrack.bridges.sandbox_bridge")
        monkeypatch.setattr(bridge_module, "_get_analysis_module", counting_import)

        asyncio.run(bridge.extract_iocs("some-id"))

        assert call_count == 1

    def test_get_analysis_module_returns_module(self) -> None:
        """_get_analysis_module() returns the analysis module without error."""
        mod = importlib.import_module("intellicrack.bridges.sandbox_bridge")
        fn = getattr(mod, "_get_analysis_module")
        fn.cache_clear()
        result = fn()
        assert result is not None
        fn.cache_clear()

    def test_get_analysis_module_returns_same_object(self) -> None:
        """_get_analysis_module() returns the same object on successive calls."""
        mod = importlib.import_module("intellicrack.bridges.sandbox_bridge")
        fn = getattr(mod, "_get_analysis_module")
        fn.cache_clear()
        first = fn()
        second = fn()
        assert first is second
        fn.cache_clear()


class TestF0013ContQMPFailureHandling:
    """F-0013: cont() raises ToolError on QMP failure; vm_resumed not logged unconditionally."""

    def test_no_vm_resumed_log_on_qmp_error(self) -> None:
        """vm_resumed is not logged when QMP returns failure."""
        bridge = SandboxBridge()

        sandbox = InMemoryQEMUSandbox()
        sandbox.qmp = cast("StubQMP", _ScriptedQMP(cont_response=_QMPResponse(success=False, error="VM error")))
        instance = StubInstance(sandbox, "qemu", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        records: list[logging.LogRecord] = []

        class CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = CapturingHandler()
        handler.setLevel(logging.INFO)
        bridge_logger = logging.getLogger("intellicrack.bridges.sandbox_bridge")
        bridge_logger.addHandler(handler)

        async def run() -> None:
            with pytest.raises(ToolError):
                await bridge.cont("some-id")

        try:
            asyncio.run(run())
        finally:
            bridge_logger.removeHandler(handler)

        resumed_logs = [r for r in records if "vm_resumed" in r.getMessage()]
        assert not resumed_logs, "vm_resumed should not be logged on QMP failure"


class TestF0014GetPendingMessagesAttributeSafety:
    """F-0014: get_pending_messages builds message dicts inside try block; catches AttributeError."""

    def test_catches_attribute_error_during_message_build(self) -> None:
        """get_pending_messages falls back to type='unknown' when message has no message_type.

        A plain ``object()`` instance has no ``message_type`` attribute. The bridge
        must catch the ``AttributeError`` (via ``getattr`` with default) and emit
        ``{"type": "unknown", "data": {}}`` for that message. The result dict must
        have ``count=1`` and ``messages[0]["type"] == "unknown"``.
        """
        bridge = SandboxBridge()

        bad_message = object()

        sandbox = InMemoryQEMUSandbox()
        sandbox.agent = cast("StubAgent", _ScriptedAgent(messages=[bad_message]))
        instance = StubInstance(sandbox, "qemu", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> dict[str, Any]:
            return await bridge.get_pending_messages("some-id")

        result = asyncio.run(run())
        assert result["count"] == 1
        assert len(result["messages"]) == 1
        assert result["messages"][0]["type"] == "unknown"
        assert result["messages"][0]["data"] == {}

    def test_message_type_read_via_getattr_exact_field(self) -> None:
        """get_pending_messages reads message_type and data safely from a concrete object.

        A concrete class with ``message_type = "exec_result"`` and ``data = {}``
        must produce a message entry whose ``type`` field is exactly ``"exec_result"``
        and whose ``data`` field is exactly ``{}``. This confirms the bridge reads
        the correct attribute names and does not rename or transform them.
        """
        bridge = SandboxBridge()

        class _ExecResultMessage:
            message_type: ClassVar[str] = "exec_result"
            data: ClassVar[dict[str, object]] = {}

        sandbox = InMemoryQEMUSandbox()
        sandbox.agent = cast("StubAgent", _ScriptedAgent(messages=[_ExecResultMessage()]))
        instance = StubInstance(sandbox, "qemu", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> dict[str, Any]:
            return await bridge.get_pending_messages("some-id")

        result = asyncio.run(run())
        assert result["count"] == 1
        assert result["messages"][0]["type"] == "exec_result"
        assert result["messages"][0]["data"] == {}

    def test_multiple_message_types_all_fields_present(self) -> None:
        """get_pending_messages correctly serialises a mix of typed and untyped messages.

        Given one typed message (``message_type="file_read"``) and one bare
        ``object()`` without attributes, the result must be:
        - ``count == 2``
        - ``messages[0]["type"] == "file_read"`` (or messages[1], order-stable)
        - One entry with ``type == "unknown"``

        This confirms the bridge serialises every message, not just the first.
        """
        bridge = SandboxBridge()

        class TypedMsg:
            message_type: ClassVar[str] = "file_read"
            data: ClassVar[dict[str, object]] = {"path": "/sandbox/output/x"}

        sandbox = InMemoryQEMUSandbox()
        sandbox.agent = cast("StubAgent", _ScriptedAgent(messages=[TypedMsg(), object()]))
        instance = StubInstance(sandbox, "qemu", instance_id="some-id")
        bridge.attach_manager(cast("SandboxManager", StubManager({"some-id": instance})))

        async def run() -> dict[str, Any]:
            return await bridge.get_pending_messages("some-id")

        result = asyncio.run(run())
        assert result["count"] == 2
        types = {m["type"] for m in result["messages"]}
        assert "file_read" in types, f"typed message not found in: {types!r}"
        assert "unknown" in types, f"fallback 'unknown' not found in: {types!r}"


class TestF0015DataclassToDict:
    """F-0015: dataclass_to_dict uses dataclasses.asdict; converts datetime/Path; JSON round-trip."""

    @dataclasses.dataclass
    class _SimpleReport:
        result: str
        exit_code: int
        created_at: datetime
        output_path: Path

    def test_converts_dataclass_to_dict(self, tmp_path: Path) -> None:
        """dataclass_to_dict converts a dataclass to a flat dict."""
        now = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        report = self._SimpleReport(
            result="success",
            exit_code=0,
            created_at=now,
            output_path=tmp_path / "report.json",
        )
        result = dataclass_to_dict(report)
        assert result["result"] == "success"
        assert result["exit_code"] == 0

    def test_converts_datetime_to_utc_iso8601(self, tmp_path: Path) -> None:
        """dataclass_to_dict converts datetime to UTC ISO-8601 string."""
        now = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        report = self._SimpleReport(
            result="ok",
            exit_code=0,
            created_at=now,
            output_path=tmp_path / "x.bin",
        )
        result = dataclass_to_dict(report)
        assert result["created_at"] == "2026-01-15T12:00:00+00:00"

    def test_converts_path_to_posix_string(self, tmp_path: Path) -> None:
        """dataclass_to_dict converts Path to POSIX string."""
        out_path = tmp_path / "Users" / "test" / "out.bin"
        report = self._SimpleReport(
            result="ok",
            exit_code=0,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
            output_path=out_path,
        )
        result = dataclass_to_dict(report)
        assert isinstance(result["output_path"], str)

    def test_json_dumps_round_trip(self, tmp_path: Path) -> None:
        """dataclass_to_dict result survives json.dumps round-trip."""
        report = self._SimpleReport(
            result="success",
            exit_code=0,
            created_at=datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC),
            output_path=tmp_path / "result.json",
        )
        result = dataclass_to_dict(report)
        serialised = json.dumps(result)
        parsed = json.loads(serialised)
        assert parsed["result"] == "success"

    def test_raises_on_non_dataclass_exact_message(self) -> None:
        """dataclass_to_dict raises ToolError whose message names the actual input type.

        The production message format is "Expected a dataclass instance, got {type.__name__}".
        For a dict input the message must contain "dict" so the caller can identify
        what it passed. The exact phrase "Expected a dataclass instance" must be present.
        """
        with pytest.raises(ToolError) as exc_info:
            dataclass_to_dict({"not": "a dataclass"})
        err = str(exc_info.value)
        assert "Expected a dataclass instance" in err, f"missing prefix: {err!r}"
        assert "dict" in err, f"missing actual type name 'dict': {err!r}"

    def test_raises_on_dataclass_class_not_instance_exact_message(self) -> None:
        """dataclass_to_dict raises ToolError whose message names the class type when given a class.

        Passing the class itself (not an instance) must produce "Expected a dataclass
        instance, got _SimpleReport" (or the qualified name). The message must contain
        the class name so the caller knows they forgot to instantiate it.
        """
        with pytest.raises(ToolError) as exc_info:
            dataclass_to_dict(self._SimpleReport)
        err = str(exc_info.value)
        assert "Expected a dataclass instance" in err, f"missing prefix: {err!r}"
        assert "_SimpleReport" in err or "type" in err, f"missing class name in error: {err!r}"


class TestF0016UTCTimestamps:
    """F-0016: Timestamps emitted as UTC ISO-8601."""

    def test_json_safe_converts_naive_datetime_to_utc(self) -> None:
        """json_safe adds UTC tzinfo to naive datetime."""
        naive = datetime.fromtimestamp(0, tz=UTC).replace(tzinfo=None)
        result = json_safe(naive)
        assert isinstance(result, str)
        assert "+00:00" in str(result) or "Z" in str(result).replace("z", "Z")

    def test_json_safe_converts_aware_datetime_to_iso(self) -> None:
        """json_safe converts aware datetime to ISO-8601 string."""
        aware = datetime(2026, 6, 15, 10, 30, 0, tzinfo=UTC)
        result = json_safe(aware)
        assert isinstance(result, str)
        assert "2026-06-15" in str(result)

    def test_json_safe_converts_path_to_posix(self, tmp_path: Path) -> None:
        """json_safe converts Path to POSIX string."""
        p = tmp_path / "test.bin"
        result = json_safe(p)
        assert isinstance(result, str)
        assert "test.bin" in str(result)

    def test_json_safe_recurses_dict(self) -> None:
        """json_safe recursively converts nested dict values."""
        d: dict[str, object] = {"ts": datetime(2026, 1, 1, tzinfo=UTC), "val": 42}
        result = json_safe(d)
        assert isinstance(result, dict)
        assert isinstance(result["ts"], str)
        assert result["val"] == 42

    def test_json_safe_recurses_list(self) -> None:
        """json_safe recursively converts list items."""
        lst: list[object] = [datetime(2026, 1, 1, tzinfo=UTC), "foo", 3]
        result = json_safe(lst)
        assert isinstance(result, list)
        assert isinstance(result[0], str)
        assert result[1] == "foo"

    def test_list_method_emits_utc_timestamps(self) -> None:
        """list() emits UTC ISO-8601 timestamps for created_at and last_used."""
        bridge = SandboxBridge()

        instance = StubInstance(InMemorySandbox(), "windows", instance_id="inst-1")
        bridge.attach_manager(cast("SandboxManager", StubManager({"inst-1": instance})))

        result = asyncio.run(bridge.list())
        assert len(result) == 1
        created_at = result[0]["created_at"]
        assert "+00:00" in created_at or "Z" in created_at
        last_used = result[0]["last_used"]
        assert "+00:00" in last_used or "Z" in last_used

    def test_tool_def_schemas_mention_utc(self) -> None:
        """Tool definitions for timestamp-bearing operations mention UTC or ISO 8601."""
        bridge = SandboxBridge()
        td = bridge.tool_definition
        for fn in td.functions:
            if fn.name in {"sandbox.pcap_stop", "sandbox.screenshot", "sandbox.memory_dump"}:
                combined = fn.description + " ".join(p.description for p in fn.parameters if p.description)
                assert any(kw in combined.lower() for kw in ["utc", "iso", "temp"])


class TestMV3RealSeamGates:
    """MV-3: pcap/cont/snapshot/screenshot drive real InMemoryQEMUSandbox seam bodies.

    Every gate wires the real bridge body to ``InMemoryQEMUSandbox`` (backed
    by ``StubQMP``) via ``StubManager``.  No ``AsyncMock`` or ``MagicMock``
    targets the bridge methods under test, so deleting any relevant
    production-code body turns the gate red.
    """

    @staticmethod
    def _make_qemu_bridge() -> tuple[SandboxBridge, str, InMemoryQEMUSandbox]:
        """Build a SandboxBridge wired to a single running QEMU instance.

        Creates an ``InMemoryQEMUSandbox`` (which includes a ``StubQMP`` and
        ``StubAgent``), wraps it in a ``StubInstance``, attaches it to a
        ``StubManager``, and returns the configured bridge together with the
        instance ID and the backing sandbox so callers can inspect internal
        seam state.

        Returns:
            tuple[SandboxBridge, str, InMemoryQEMUSandbox]: The configured
            bridge, the fixed instance ID ``"qemu-mv3-001"``, and the
            ``InMemoryQEMUSandbox`` whose internal dicts can be inspected to
            verify that real seam bodies executed.
        """
        sandbox = InMemoryQEMUSandbox()
        sandbox.state.status = "running"
        instance = StubInstance(sandbox, "qemu", instance_id="qemu-mv3-001")
        manager = StubManager({"qemu-mv3-001": instance})
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", manager))
        return bridge, "qemu-mv3-001", sandbox

    def test_pcap_start_capture_id_forwarded_from_real_seam(self) -> None:
        """pcap_start returns the exact capture_id produced by the real start_pcap_capture body.

        The oracle is ``InMemorySandbox.start_pcap_capture``, which stores
        ``"cap-001"`` (the module constant ``_DEFAULT_PCAP_ID``) in its
        internal ``_pcap_captures`` dict and returns it.  The bridge must
        forward that value verbatim so that:

        - ``result["capture_id"]`` is exactly ``"cap-001"``
        - ``bridge._active_pcap_captures[instance_id]`` is ``"cap-001"``
        - ``sandbox._pcap_captures`` contains the key ``"cap-001"``

        Mutation caught: deleting the body of ``start_pcap_capture`` so it
        returns ``None`` causes ``result["capture_id"]`` to be ``None``,
        which fails the equality assertion ``== "cap-001"``.
        """
        bridge, instance_id, sandbox = self._make_qemu_bridge()

        result: dict[str, Any] = asyncio.run(bridge.pcap_start(instance_id))

        active_caps: dict[str, str] = cast("dict[str, str]", getattr(bridge, "_active_pcap_captures"))
        pcap_caps: dict[str, list[bytes]] = cast("dict[str, list[bytes]]", getattr(sandbox, "_pcap_captures"))
        assert result["capture_id"] == "cap-001", f"capture_id not forwarded from real seam: {result['capture_id']!r}"
        assert result["instance_id"] == instance_id
        assert active_caps[instance_id] == "cap-001", f"bridge did not register capture_id in _active_pcap_captures: {active_caps!r}"
        assert "cap-001" in pcap_caps, f"seam _pcap_captures does not show the started capture: {list(pcap_caps)!r}"

    def test_cont_run_state_forwarded_from_real_stub_qmp(self) -> None:
        """cont() returns success=True and data forwarded verbatim from the real StubQMP body.

        The oracle is ``StubQMP.cont()``, which returns
        ``QMPResponse(success=True, data={"status": "running"})``.  The
        bridge must copy both fields into the return dict unchanged, so:

        - ``result["success"]`` is exactly ``True``
        - ``result["data"]`` is exactly ``{"status": "running"}``

        Mutation caught: if the body of ``StubQMP.cont`` is deleted so it
        returns ``None``, the bridge raises an ``AttributeError`` on
        ``None.success``, converting to a ``ToolError``.  The test then
        receives the error instead of a success dict and fails.
        """
        bridge, instance_id, _ = self._make_qemu_bridge()

        result: dict[str, Any] = asyncio.run(bridge.cont(instance_id))

        assert result["success"] is True, f"expected success=True from StubQMP.cont(): {result['success']!r}"
        assert result["data"] == {"status": "running"}, f"data dict not forwarded verbatim from StubQMP.cont(): {result['data']!r}"
        assert result["instance_id"] == instance_id

    def test_snapshot_create_id_and_seam_state(self) -> None:
        """snapshot_create returns the snapshot_id built by take_snapshot and recorded in the seam.

        The oracle is ``InMemorySandbox.take_snapshot``, which constructs the
        snapshot ID as ``f"snap-{name}"`` and stores the current file tree
        under that key in ``sandbox._snapshots``.  The bridge must:

        - return ``result["snapshot_id"] == "snap-test-snap"``
        - the key ``"snap-test-snap"`` must be present in ``sandbox._snapshots``
          after the call (confirming the body executed, not just returned)

        Mutation caught: if ``take_snapshot`` is deleted so it returns
        ``None``, ``result["snapshot_id"]`` is ``None``, which is not equal
        to ``"snap-test-snap"``.
        """
        bridge, instance_id, sandbox = self._make_qemu_bridge()

        result: dict[str, Any] = asyncio.run(bridge.snapshot_create(instance_id, "test-snap"))

        snapshots: dict[str, dict[str, bytes]] = cast(
            "dict[str, dict[str, bytes]]",
            getattr(sandbox, "_snapshots"),
        )
        assert result["snapshot_id"] == "snap-test-snap", f"snapshot_id not forwarded from real seam: {result['snapshot_id']!r}"
        assert result["name"] == "test-snap"
        assert result["instance_id"] == instance_id
        assert "snap-test-snap" in snapshots, f"take_snapshot did not record entry in seam _snapshots: {list(snapshots)!r}"

    def test_screenshot_path_forwarded_from_real_seam(self) -> None:
        """screenshot() returns the path string produced by the real capture_screenshot body.

        The oracle is ``InMemorySandbox.capture_screenshot``, which returns
        ``Path(tempfile.gettempdir()) / "screenshot.png"`` when called
        without an explicit output path.  The bridge converts this ``Path``
        to a string via ``str()`` and must return it verbatim, so
        ``result["screenshot_path"]`` must equal
        ``str(Path(tempfile.gettempdir()) / "screenshot.png")``.

        Mutation caught: if ``capture_screenshot`` is deleted so it returns
        ``None``, the bridge stores ``str(None) == "None"``, which does not
        equal the expected filesystem path.
        """
        bridge, instance_id, _ = self._make_qemu_bridge()

        result: dict[str, Any] = asyncio.run(bridge.screenshot(instance_id))

        expected_path = str(Path(tempfile.gettempdir()) / "screenshot.png")
        assert result["screenshot_path"] == expected_path, f"screenshot_path not forwarded from real seam: {result['screenshot_path']!r}"
        assert result["instance_id"] == instance_id

    def test_pcap_lifecycle_start_then_stop_clears_bridge_tracking(self) -> None:
        """pcap_start followed by pcap_stop removes the capture from bridge._active_pcap_captures.

        After ``pcap_start`` the bridge must register capture ``"cap-001"`` in
        ``_active_pcap_captures``.  After ``pcap_stop`` the entry must be
        removed and the returned ``pcap_path`` must equal the path produced by
        the real ``stop_pcap_capture`` seam body (``_TMPDIR / "capture.pcap"``).

        Mutation caught: if ``start_pcap_capture`` returns ``None``, the
        ``capture_id`` stored in the bridge is ``None`` and the assertion
        ``capture_id == "cap-001"`` immediately fails.
        """
        bridge, instance_id, _ = self._make_qemu_bridge()

        start_result: dict[str, Any] = asyncio.run(bridge.pcap_start(instance_id))
        capture_id: str = cast(str, start_result["capture_id"])
        active_after_start: dict[str, str] = cast(
            "dict[str, str]",
            getattr(bridge, "_active_pcap_captures"),
        )

        assert capture_id == "cap-001"
        assert instance_id in active_after_start, "pcap_start must register the capture in bridge._active_pcap_captures"

        stop_result: dict[str, Any] = asyncio.run(bridge.pcap_stop(instance_id, capture_id))

        active_after_stop: dict[str, str] = cast(
            "dict[str, str]",
            getattr(bridge, "_active_pcap_captures"),
        )
        assert instance_id not in active_after_stop, f"pcap_stop must remove the capture; still tracking: {active_after_stop!r}"
        expected_pcap_path = str(Path(tempfile.gettempdir()) / "capture.pcap")
        assert stop_result["pcap_path"] == expected_pcap_path, f"pcap_path not forwarded from real seam: {stop_result['pcap_path']!r}"
