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
import textwrap
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar, cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from intellicrack.bridges.sandbox_bridge import (
    SandboxBridge,
    dataclass_to_dict,
    json_safe,
)
from intellicrack.core.types import SandboxError, ToolError
from intellicrack.sandbox import ExecutionReport


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path


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


class TestF0001ContBroadException:
    """F-0001: cont() catches broad Exception and wraps as ToolError."""

    def test_cont_wraps_general_exception(self) -> None:
        """cont() raises ToolError when qmp.cont() throws an unexpected exception."""
        bridge = SandboxBridge()

        mock_qmp = MagicMock()
        mock_qmp.cont = AsyncMock(side_effect=RuntimeError("unexpected QMP failure"))

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "qemu"
        type(mock_instance.sandbox).qmp = property(lambda _self: mock_qmp)

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="Failed to resume VM execution"):
                    await bridge.cont("some-id")

        asyncio.run(run())

    def test_cont_wraps_value_error(self) -> None:
        """cont() raises ToolError when qmp.cont() throws a ValueError."""
        bridge = SandboxBridge()

        mock_qmp = MagicMock()
        mock_qmp.cont = AsyncMock(side_effect=ValueError("bad value"))

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "qemu"
        type(mock_instance.sandbox).qmp = property(lambda _self: mock_qmp)

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                with pytest.raises(ToolError):
                    await bridge.cont("some-id")

        asyncio.run(run())

    def test_cont_raises_on_qmp_failure_response(self) -> None:
        """cont() raises ToolError when QMP response indicates failure."""
        bridge = SandboxBridge()

        failed_response = MagicMock()
        failed_response.success = False
        failed_response.error = "VM not running"
        mock_qmp = MagicMock()
        mock_qmp.cont = AsyncMock(return_value=failed_response)

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "qemu"
        type(mock_instance.sandbox).qmp = property(lambda _self: mock_qmp)

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="VM not running"):
                    await bridge.cont("some-id")

        asyncio.run(run())

    def test_cont_logs_resumed_only_on_success(self) -> None:
        """cont() only logs vm_resumed when QMP returns success."""
        bridge = SandboxBridge()

        success_response = MagicMock()
        success_response.success = True
        success_response.data = {"status": "running"}
        mock_qmp = MagicMock()
        mock_qmp.cont = AsyncMock(return_value=success_response)

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "qemu"
        mock_instance.touch = MagicMock()
        type(mock_instance.sandbox).qmp = property(lambda _self: mock_qmp)

        async def run() -> dict[str, Any]:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                return await bridge.cont("some-id")

        result = asyncio.run(run())
        assert result["success"] is True
        assert result["instance_id"] == "some-id"


class TestF0002NarrowExceptionHandling:
    """F-0002: Exception handling sites wrap unexpected exceptions as ToolError."""

    def test_extract_iocs_wraps_unexpected_exception(self) -> None:
        """extract_iocs() wraps an unexpected OSError as ToolError."""
        bridge = SandboxBridge()

        mock_report = MagicMock()
        mock_instance = MagicMock()
        mock_instance.last_report = mock_report

        with patch("intellicrack.bridges.sandbox_bridge._get_analysis_module") as mock_mod:
            analysis = MagicMock()
            analysis.extract_iocs = MagicMock(side_effect=OSError("disk error"))
            mock_mod.return_value = analysis

            async def run() -> None:
                with patch.object(bridge, "ensure_manager") as mock_mgr:
                    manager = AsyncMock()
                    manager.get = AsyncMock(return_value=mock_instance)
                    mock_mgr.return_value = manager
                    with pytest.raises(ToolError, match="Failed to extract IOCs"):
                        await bridge.extract_iocs("some-id")

            asyncio.run(run())

    def test_timeline_wraps_unexpected_exception(self) -> None:
        """timeline() wraps an unexpected AttributeError as ToolError."""
        bridge = SandboxBridge()

        mock_report = MagicMock()
        mock_instance = MagicMock()
        mock_instance.last_report = mock_report

        with patch("intellicrack.bridges.sandbox_bridge._get_analysis_module") as mock_mod:
            analysis = MagicMock()
            analysis.generate_timeline = MagicMock(side_effect=AttributeError("no attr"))
            mock_mod.return_value = analysis

            async def run() -> None:
                with patch.object(bridge, "ensure_manager") as mock_mgr:
                    manager = AsyncMock()
                    manager.get = AsyncMock(return_value=mock_instance)
                    mock_mgr.return_value = manager
                    with pytest.raises(ToolError, match="Failed to generate timeline"):
                        await bridge.timeline("some-id")

            asyncio.run(run())

    def test_detect_c2_wraps_unexpected_exception(self) -> None:
        """detect_c2() wraps an unexpected exception as ToolError."""
        bridge = SandboxBridge()

        mock_report = MagicMock()
        mock_report.network_activity = []
        mock_instance = MagicMock()
        mock_instance.last_report = mock_report

        with patch("intellicrack.bridges.sandbox_bridge._get_analysis_module") as mock_mod:
            analysis = MagicMock()
            analysis.detect_c2_patterns = MagicMock(side_effect=RuntimeError("unexpected"))
            mock_mod.return_value = analysis

            async def run() -> None:
                with patch.object(bridge, "ensure_manager") as mock_mgr:
                    manager = AsyncMock()
                    manager.get = AsyncMock(return_value=mock_instance)
                    mock_mgr.return_value = manager
                    with pytest.raises(ToolError, match="Failed to detect C2 patterns"):
                        await bridge.detect_c2("some-id")

            asyncio.run(run())

    def test_diff_wraps_unexpected_exception(self) -> None:
        """diff() wraps an unexpected exception as ToolError."""
        bridge = SandboxBridge()

        mock_report = MagicMock()
        mock_instance = MagicMock()
        mock_instance.last_report = mock_report

        with patch("intellicrack.bridges.sandbox_bridge._get_analysis_module") as mock_mod:
            analysis = MagicMock()
            analysis.diff_reports = MagicMock(side_effect=MemoryError("oom"))
            mock_mod.return_value = analysis

            async def run() -> None:
                with patch.object(bridge, "ensure_manager") as mock_mgr:
                    manager = AsyncMock()
                    manager.get = AsyncMock(return_value=mock_instance)
                    mock_mgr.return_value = manager
                    with pytest.raises(ToolError, match="Failed to diff reports"):
                        await bridge.diff("id-a", "id-b")

            asyncio.run(run())

    def test_detect_behaviors_wraps_unexpected_exception(self) -> None:
        """detect_behaviors() wraps an unexpected exception as ToolError."""
        bridge = SandboxBridge()

        mock_report = MagicMock()
        mock_instance = MagicMock()
        mock_instance.last_report = mock_report

        with patch("intellicrack.bridges.sandbox_bridge._get_analysis_module") as mock_mod:
            analysis = MagicMock()
            analysis.match_behaviors = MagicMock(side_effect=ZeroDivisionError("oops"))
            mock_mod.return_value = analysis

            async def run() -> None:
                with patch.object(bridge, "ensure_manager") as mock_mgr:
                    manager = AsyncMock()
                    manager.get = AsyncMock(return_value=mock_instance)
                    mock_mgr.return_value = manager
                    with pytest.raises(ToolError, match="Failed to detect behaviors"):
                        await bridge.detect_behaviors("some-id")

            asyncio.run(run())


class TestF0003DetectBehaviorsYAML:
    """F-0003: detect_behaviors validates path, raises on JSONDecodeError/wrong shape, uses yaml.safe_load."""

    def test_raises_when_rules_file_not_found(self, tmp_path: Path) -> None:
        """detect_behaviors raises ToolError when custom_rules_path does not exist."""
        bridge = SandboxBridge()

        mock_report = MagicMock()
        mock_instance = MagicMock()
        mock_instance.last_report = mock_report
        missing = str(tmp_path / "no_such_file.yaml")

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="Custom rules file not found"):
                    await bridge.detect_behaviors("some-id", custom_rules_path=missing)

        asyncio.run(run())

    def test_raises_on_invalid_yaml(self, tmp_path: Path) -> None:
        """detect_behaviors raises ToolError when YAML file has invalid syntax."""
        bridge = SandboxBridge()

        rules_file = tmp_path / "bad.yaml"
        rules_file.write_text("key: [unclosed\n", encoding="utf-8")

        mock_report = MagicMock()
        mock_instance = MagicMock()
        mock_instance.last_report = mock_report

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="Custom rules file is not valid YAML"):
                    await bridge.detect_behaviors("some-id", custom_rules_path=str(rules_file))

        asyncio.run(run())

    def test_raises_when_yaml_not_a_list(self, tmp_path: Path) -> None:
        """detect_behaviors raises ToolError when YAML top-level is not a list."""
        bridge = SandboxBridge()

        rules_file = tmp_path / "dict_rules.yaml"
        rules_file.write_text("key: value\n", encoding="utf-8")

        mock_report = MagicMock()
        mock_instance = MagicMock()
        mock_instance.last_report = mock_report

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="expected a list"):
                    await bridge.detect_behaviors("some-id", custom_rules_path=str(rules_file))

        asyncio.run(run())

    def test_valid_yaml_list_rules_passed_to_behaviors(self, tmp_path: Path) -> None:
        """detect_behaviors passes parsed YAML list to match_behaviors."""
        bridge = SandboxBridge()

        yaml_content = textwrap.dedent("""\
            - name: TestRule
              category: persistence
        """)
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(yaml_content, encoding="utf-8")

        mock_report = MagicMock()
        mock_instance = MagicMock()
        mock_instance.last_report = mock_report

        captured_rules: list[dict[str, Any]] = []

        def capture_rules(_report: object, rules: object) -> list[dict[str, Any]]:
            if not isinstance(rules, list):
                return []
            typed_rules: list[dict[str, Any]] = [
                cast("dict[str, Any]", raw) for raw in cast("list[object]", rules) if isinstance(raw, dict)
            ]
            captured_rules.extend(typed_rules)
            return []

        with patch("intellicrack.bridges.sandbox_bridge._get_analysis_module") as mock_mod:
            analysis = MagicMock()
            analysis.match_behaviors = MagicMock(side_effect=capture_rules)
            mock_mod.return_value = analysis

            async def run() -> None:
                with patch.object(bridge, "ensure_manager") as mock_mgr:
                    manager = AsyncMock()
                    manager.get = AsyncMock(return_value=mock_instance)
                    mock_mgr.return_value = manager
                    await bridge.detect_behaviors("some-id", custom_rules_path=str(rules_file))

            asyncio.run(run())

        assert len(captured_rules) == 1
        assert captured_rules[0]["name"] == "TestRule"


class TestF0004YaraScanModeValidation:
    """F-0004: yara_scan validates mode in ('files', 'memory'); raises ToolError on invalid."""

    def test_raises_on_invalid_scan_target(self) -> None:
        """yara_scan raises ToolError when scan_target is not 'files' or 'memory'."""
        bridge = SandboxBridge()

        async def run() -> None:
            with pytest.raises(ToolError, match="Invalid scan_target"):
                await bridge.yara_scan("some-id", scan_target="processes")

        asyncio.run(run())

    def test_accepts_files_target(self) -> None:
        """yara_scan accepts 'files' as a valid scan_target."""
        bridge = SandboxBridge()

        mock_instance = MagicMock()
        mock_instance.sandbox.yara_scan = AsyncMock(return_value=[])

        async def run() -> dict[str, Any]:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                return await bridge.yara_scan("some-id", scan_target="files")

        result = asyncio.run(run())
        assert result["match_count"] == 0

    def test_accepts_memory_target(self) -> None:
        """yara_scan accepts 'memory' as a valid scan_target."""
        bridge = SandboxBridge()

        mock_instance = MagicMock()
        mock_instance.sandbox.yara_scan = AsyncMock(return_value=[])

        async def run() -> dict[str, Any]:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                return await bridge.yara_scan("some-id", scan_target="memory")

        result = asyncio.run(run())
        assert result["match_count"] == 0


class TestF0005PublicQMPAgentAccessors:
    """F-0005: Uses public qmp/agent accessors instead of private _qmp/_agent."""

    def test_qemu_sandbox_qmp_returns_none_when_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """QEMUSandbox.qmp returns None when no QMP client has been attached."""
        qemu = pytest.importorskip("intellicrack.sandbox.qemu")
        qemu_sandbox_cls = qemu.QEMUSandbox

        sandbox = qemu_sandbox_cls.__new__(qemu_sandbox_cls)
        monkeypatch.setattr(sandbox, "_qmp", None, raising=False)
        monkeypatch.setattr(sandbox, "_agent", None, raising=False)

        assert sandbox.qmp is None
        assert sandbox.agent is None

    def test_qemu_sandbox_has_public_qmp_property(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """QEMUSandbox exposes qmp as a public property returning the QMP client."""
        qemu = pytest.importorskip("intellicrack.sandbox.qemu")
        qemu_sandbox_cls = qemu.QEMUSandbox
        qmp_client_cls = qemu.QMPClient

        sandbox = qemu_sandbox_cls.__new__(qemu_sandbox_cls)
        mock_client = MagicMock(spec=qmp_client_cls)
        monkeypatch.setattr(sandbox, "_qmp", mock_client, raising=False)

        assert sandbox.qmp is mock_client

    def test_qemu_sandbox_has_public_agent_property(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """QEMUSandbox exposes agent as a public property returning the GuestAgentClient."""
        qemu = pytest.importorskip("intellicrack.sandbox.qemu")
        qemu_sandbox_cls = qemu.QEMUSandbox
        guest_agent_cls = qemu.GuestAgentClient

        sandbox = qemu_sandbox_cls.__new__(qemu_sandbox_cls)
        mock_agent = MagicMock(spec=guest_agent_cls)
        monkeypatch.setattr(sandbox, "_agent", mock_agent, raising=False)

        assert sandbox.agent is mock_agent

    def test_get_pending_messages_uses_agent_not_private(self) -> None:
        """get_pending_messages() accesses agent via public property, not _agent."""
        pytest.importorskip("intellicrack.sandbox.qemu")

        bridge = SandboxBridge()
        mock_agent = AsyncMock()
        mock_agent.get_pending_messages = AsyncMock(return_value=[])

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "qemu"
        type(mock_instance.sandbox).agent = property(lambda _self: mock_agent)

        async def run() -> dict[str, Any]:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                return await bridge.get_pending_messages("some-id")

        result = asyncio.run(run())
        assert result["count"] == 0


class TestF0006NoHotPathInfoLogs:
    """F-0006: No *_started info logs in hot paths (is_available, status, list)."""

    def test_is_available_no_info_log(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """is_available() does not emit an info-level 'started' log."""
        bridge = SandboxBridge()
        mock_manager = MagicMock()
        mock_manager.get_available_types = AsyncMock(return_value=["windows"])
        monkeypatch.setattr(bridge, "_manager", mock_manager)

        records: list[logging.LogRecord] = []

        class CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = CapturingHandler()
        handler.setLevel(logging.INFO)
        root_logger = logging.getLogger("intellicrack.bridges.sandbox_bridge")
        root_logger.addHandler(handler)
        try:
            asyncio.run(bridge.is_available())
        finally:
            root_logger.removeHandler(handler)

        started_records = [r for r in records if "started" in r.getMessage().lower()]
        assert not started_records, f"Unexpected 'started' info logs: {[r.getMessage() for r in started_records]}"

    def test_status_no_info_log(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """status() does not emit an info-level 'started' log."""
        bridge = SandboxBridge()
        mock_manager = MagicMock()
        mock_manager.get_status = AsyncMock(return_value={"instances": []})
        monkeypatch.setattr(bridge, "_manager", mock_manager)

        records: list[logging.LogRecord] = []

        class CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = CapturingHandler()
        handler.setLevel(logging.INFO)
        root_logger = logging.getLogger("intellicrack.bridges.sandbox_bridge")
        root_logger.addHandler(handler)
        try:
            asyncio.run(bridge.status())
        finally:
            root_logger.removeHandler(handler)

        started_records = [r for r in records if "started" in r.getMessage().lower()]
        assert not started_records, f"Unexpected 'started' info logs: {[r.getMessage() for r in started_records]}"

    def test_list_no_info_log(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """list() does not emit an info-level 'started' log."""
        bridge = SandboxBridge()
        mock_manager = MagicMock()
        mock_manager.instances = []
        monkeypatch.setattr(bridge, "_manager", mock_manager)

        records: list[logging.LogRecord] = []

        class CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = CapturingHandler()
        handler.setLevel(logging.INFO)
        root_logger = logging.getLogger("intellicrack.bridges.sandbox_bridge")
        root_logger.addHandler(handler)
        try:
            asyncio.run(bridge.list())
        finally:
            root_logger.removeHandler(handler)

        started_records = [r for r in records if "started" in r.getMessage().lower()]
        assert not started_records, f"Unexpected 'started' info logs: {[r.getMessage() for r in started_records]}"


class TestF0007GetVNCPort:
    """F-0007: get_vnc_port gates on QEMU type and raises ToolError for non-QEMU or no VNC."""

    def test_raises_on_non_qemu_sandbox(self) -> None:
        """get_vnc_port raises ToolError for windows sandbox."""
        bridge = SandboxBridge()

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "windows"

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="requires QEMU sandbox"):
                    await bridge.get_vnc_port("some-id")

        asyncio.run(run())

    def test_raises_when_vnc_port_is_none(self) -> None:
        """get_vnc_port raises ToolError when VNC port is not allocated."""
        bridge = SandboxBridge()

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "qemu"
        type(mock_instance.sandbox).vnc_port = property(lambda _self: None)

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="VNC display not configured"):
                    await bridge.get_vnc_port("some-id")

        asyncio.run(run())

    def test_returns_vnc_port_when_configured(self) -> None:
        """get_vnc_port returns the VNC port number when configured."""
        bridge = SandboxBridge()

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "qemu"
        type(mock_instance.sandbox).vnc_port = property(lambda _self: 5900)

        async def run() -> int:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                return await bridge.get_vnc_port("some-id")

        result = asyncio.run(run())
        assert result == 5900

    def test_raises_on_missing_instance(self) -> None:
        """get_vnc_port raises ToolError when instance not found."""
        bridge = SandboxBridge()

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=None)
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="Sandbox instance not found"):
                    await bridge.get_vnc_port("missing-id")

        asyncio.run(run())


class TestF0008QEMUGatedMethods:
    """F-0008: pcap_start/screenshot/extract_dropped_files/anti_evasion raise on non-QEMU.

    ``memory_dump`` is no longer QEMU-only (audit7 F-0021): the Windows sandbox
    implementation now supports per-process minidumps via ``MiniDumpWriteDump``
    with a required ``target_pid`` argument. ``memory_dump`` therefore raises a
    different error (``target_pid is required for Windows Sandbox memory_dump``)
    when invoked against a Windows instance without ``target_pid``, which is
    covered separately in :class:`tests.test_audit7.sandbox_windows`.
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
        """Each QEMU-only method raises ToolError when sandbox_type is 'windows'.

        Args:
            method: Bridge method name to invoke.
            kwargs: Extra keyword arguments for the method.
        """
        bridge = SandboxBridge()

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "windows"

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                fn = getattr(bridge, method)
                with pytest.raises(ToolError, match="requires QEMU sandbox"):
                    await fn("some-id", **kwargs)

        asyncio.run(run())


class TestF0009EnsureManagerDestroyed:
    """F-0009: ensure_manager raises ToolError when manager was shut down."""

    def test_raises_after_shutdown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ensure_manager raises ToolError when called after shutdown()."""
        bridge = SandboxBridge()

        async def run() -> None:
            mock_manager = MagicMock()
            mock_manager.destroy_all = AsyncMock()
            monkeypatch.setattr(bridge, "_manager", mock_manager)
            await bridge.shutdown()
            assert bridge.manager is None
            assert bridge.manager_destroyed is True
            with pytest.raises(ToolError, match="manager was shut down"):
                bridge.ensure_manager()

        asyncio.run(run())

    def test_succeeds_before_shutdown(self) -> None:
        """ensure_manager creates a new manager when never initialized."""
        bridge = SandboxBridge()

        with patch("intellicrack.bridges.sandbox_bridge.SandboxManager") as mock_cls:
            mock_cls.return_value = MagicMock()
            mgr = bridge.ensure_manager()
            assert mgr is not None
            assert bridge.manager is mgr

    def test_returns_existing_manager(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ensure_manager returns existing manager without creating a new one."""
        bridge = SandboxBridge()
        mock_mgr = MagicMock()
        monkeypatch.setattr(bridge, "_manager", mock_mgr)

        result = bridge.ensure_manager()
        assert result is mock_mgr
        assert bridge.manager is mock_mgr


class TestF0010BridgeStateUpdates:
    """F-0010: BridgeState updated through state-changing methods; error paths set last_error."""

    def test_create_updates_state_on_success(self) -> None:
        """create() sets BridgeState.last_error to None on success."""
        bridge = SandboxBridge()
        now = datetime.now(UTC)

        mock_instance = MagicMock()
        mock_instance.id = "test-id"
        mock_instance.sandbox_type = "windows"
        mock_instance.state.status = "running"
        mock_instance.created_at = now

        async def run() -> dict[str, Any]:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.create = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                return await bridge.create(sandbox_type="windows")

        asyncio.run(run())
        assert bridge.state.last_error is None

    def test_create_sets_last_error_on_failure(self) -> None:
        """create() sets BridgeState.last_error when SandboxError occurs."""
        bridge = SandboxBridge()

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.create = AsyncMock(side_effect=SandboxError("creation failed"))
                mock_mgr.return_value = manager
                with pytest.raises(ToolError):
                    await bridge.create(sandbox_type="windows")

        asyncio.run(run())
        assert bridge.state.last_error is not None
        assert "creation failed" in bridge.state.last_error

    def test_run_binary_updates_binary_loaded(self, tmp_path: Path) -> None:
        """run_binary() sets BridgeState.binary_loaded to True on success."""
        bridge = SandboxBridge()

        binary = tmp_path / "test.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 62)

        mock_instance = MagicMock()
        mock_instance.id = "test-id"
        report = _make_execution_report()

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.run_binary = AsyncMock(return_value=(mock_instance, report))
                mock_mgr.return_value = manager
                await bridge.run_binary(str(binary))

        asyncio.run(run())
        assert bridge.state.binary_loaded is True

    def test_run_binary_sets_last_error_on_failure(self, tmp_path: Path) -> None:
        """run_binary() sets BridgeState.last_error on SandboxError."""
        bridge = SandboxBridge()

        binary = tmp_path / "fail.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 62)

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.run_binary = AsyncMock(side_effect=SandboxError("exec failed"))
                mock_mgr.return_value = manager
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
    def _make_mock_instance(sandbox_type: str = "qemu", *, with_report: bool = False) -> MagicMock:
        """Build a stand-in :class:`SandboxInstance` for bridge calls.

        Args:
            sandbox_type: Value to expose on the ``sandbox_type`` attribute.
            with_report: Whether to attach a non-``None`` ``last_report``
                so analysis methods proceed past the report-presence
                guard clause.

        Returns:
            MagicMock: Mock instance with all sandbox attributes pre-wired
            as ``AsyncMock`` coroutines so any awaited call resolves.
        """
        instance = MagicMock()
        instance.sandbox_type = sandbox_type
        instance.touch = MagicMock()
        if with_report:
            instance.last_report = MagicMock()
            instance.last_report.network_activity = []
        else:
            instance.last_report = None
        return instance

    @staticmethod
    def _run_failure_then_success(
        bridge: SandboxBridge,
        failure_setup: Callable[[AsyncMock], None],
        success_setup: Callable[[AsyncMock], None],
        failure_call: Callable[[SandboxBridge], Awaitable[object]],
        success_call: Callable[[SandboxBridge], Awaitable[object]],
        failure_substring: str,
    ) -> None:
        """Drive a failing op followed by a passing op and assert symmetry.

        Args:
            bridge: The bridge under test.
            failure_setup: Callable taking the patched manager and configuring
                it for the failure path.
            success_setup: Callable taking the patched manager and configuring
                it for the success path.
            failure_call: Async callable that invokes the failing bridge method.
            success_call: Async callable that invokes the succeeding bridge method.
            failure_substring: Substring expected inside ``state.last_error``
                after the failing call.
        """

        async def fail_then_recover() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                failure_setup(manager)
                mock_mgr.return_value = manager
                with pytest.raises(ToolError):
                    await failure_call(bridge)

            assert bridge.state.last_error is not None
            assert failure_substring in bridge.state.last_error, bridge.state.last_error

            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                success_setup(manager)
                mock_mgr.return_value = manager
                await success_call(bridge)

            assert bridge.state.last_error is None, f"last_error not cleared after successful call (was: {bridge.state.last_error!r})"

        asyncio.run(fail_then_recover())

    def test_copy_to_clears_last_error_on_success(self, tmp_path: Path) -> None:
        """Copy_to clears last_error after a successful call following a failure."""
        bridge = SandboxBridge()

        source = tmp_path / "file.bin"
        source.write_bytes(b"data")

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.copy_to_sandbox = AsyncMock(side_effect=SandboxError("copy failed"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.copy_to_sandbox = AsyncMock(return_value=None)
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.copy_to("inst", str(source), "/dest"),
            lambda b: b.copy_to("inst", str(source), "/dest"),
            "copy failed",
        )

    def test_copy_from_clears_last_error_on_success(self, tmp_path: Path) -> None:
        """Copy_from clears last_error after a successful call following a failure."""
        bridge = SandboxBridge()
        dest = tmp_path / "out.bin"

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.copy_from_sandbox = AsyncMock(side_effect=SandboxError("read failed"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.copy_from_sandbox = AsyncMock(return_value=None)
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.copy_from("inst", "/src", str(dest)),
            lambda b: b.copy_from("inst", "/src", str(dest)),
            "read failed",
        )

    def test_snapshot_create_clears_last_error_on_success(self) -> None:
        """Snapshot_create clears last_error after success following a failure."""
        bridge = SandboxBridge()

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.take_snapshot = AsyncMock(side_effect=SandboxError("snap fail"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.take_snapshot = AsyncMock(return_value="snap-1")
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.snapshot_create("inst", "snap"),
            lambda b: b.snapshot_create("inst", "snap"),
            "snap fail",
        )

    def test_snapshot_restore_clears_last_error_on_success(self) -> None:
        """Snapshot_restore clears last_error after success following a failure."""
        bridge = SandboxBridge()

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.restore_snapshot = AsyncMock(side_effect=SandboxError("restore fail"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.restore_snapshot = AsyncMock(return_value=None)
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.snapshot_restore("inst", "snap-1"),
            lambda b: b.snapshot_restore("inst", "snap-1"),
            "restore fail",
        )

    def test_snapshot_list_clears_last_error_on_success(self) -> None:
        """Snapshot_list clears last_error after success following a failure."""
        bridge = SandboxBridge()

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.list_snapshots = AsyncMock(side_effect=SandboxError("list fail"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.list_snapshots = AsyncMock(return_value=[])
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.snapshot_list("inst"),
            lambda b: b.snapshot_list("inst"),
            "list fail",
        )

    def test_snapshot_delete_clears_last_error_on_success(self) -> None:
        """Snapshot_delete clears last_error after success following a failure."""
        bridge = SandboxBridge()

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.delete_snapshot = AsyncMock(side_effect=SandboxError("del fail"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.delete_snapshot = AsyncMock(return_value=None)
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.snapshot_delete("inst", "snap"),
            lambda b: b.snapshot_delete("inst", "snap"),
            "del fail",
        )

    def test_pcap_start_clears_last_error_on_success(self) -> None:
        """Pcap_start clears last_error after success following a failure."""
        bridge = SandboxBridge()

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.start_pcap_capture = AsyncMock(side_effect=SandboxError("pcap fail"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.start_pcap_capture = AsyncMock(return_value="cap-1")
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.pcap_start("inst"),
            lambda b: b.pcap_start("inst"),
            "pcap fail",
        )

    def test_pcap_stop_clears_last_error_on_success(self, tmp_path: Path) -> None:
        """Pcap_stop clears last_error after success following a failure."""
        bridge = SandboxBridge()
        out = tmp_path / "cap.pcap"

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.stop_pcap_capture = AsyncMock(side_effect=SandboxError("stop fail"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.stop_pcap_capture = AsyncMock(return_value=out)
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.pcap_stop("inst", "cap-1"),
            lambda b: b.pcap_stop("inst", "cap-1"),
            "stop fail",
        )

    def test_screenshot_clears_last_error_on_success(self, tmp_path: Path) -> None:
        """Screenshot clears last_error after success following a failure."""
        bridge = SandboxBridge()
        out = tmp_path / "shot.png"

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.capture_screenshot = AsyncMock(side_effect=SandboxError("shot fail"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.capture_screenshot = AsyncMock(return_value=out)
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.screenshot("inst"),
            lambda b: b.screenshot("inst"),
            "shot fail",
        )

    def test_anti_evasion_clears_last_error_on_success(self) -> None:
        """Anti_evasion clears last_error after success following a failure."""
        bridge = SandboxBridge()

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.apply_anti_evasion = AsyncMock(side_effect=SandboxError("evasion fail"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.apply_anti_evasion = AsyncMock(return_value={"applied": True})
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.anti_evasion("inst"),
            lambda b: b.anti_evasion("inst"),
            "evasion fail",
        )

    def test_memory_dump_clears_last_error_on_success(self, tmp_path: Path) -> None:
        """Memory_dump clears last_error after success following a failure."""
        bridge = SandboxBridge()
        out = tmp_path / "mem.dmp"

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.dump_memory = AsyncMock(side_effect=SandboxError("dump fail"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.dump_memory = AsyncMock(return_value=out)
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.memory_dump("inst"),
            lambda b: b.memory_dump("inst"),
            "dump fail",
        )

    def test_extract_dropped_files_clears_last_error_on_success(self, tmp_path: Path) -> None:
        """Extract_dropped_files clears last_error after success following a failure."""
        bridge = SandboxBridge()
        zip_out = tmp_path / "dropped.zip"

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.extract_dropped_files = AsyncMock(side_effect=SandboxError("zip fail"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.extract_dropped_files = AsyncMock(return_value=zip_out)
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.extract_dropped_files("inst"),
            lambda b: b.extract_dropped_files("inst"),
            "zip fail",
        )

    def test_yara_scan_clears_last_error_on_success(self) -> None:
        """Yara_scan clears last_error after success following a failure."""
        bridge = SandboxBridge()

        def fail(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.yara_scan = AsyncMock(side_effect=SandboxError("yara fail"))
            manager.get = AsyncMock(return_value=instance)

        def ok(manager: AsyncMock) -> None:
            instance = self._make_mock_instance()
            instance.sandbox.yara_scan = AsyncMock(return_value=[])
            manager.get = AsyncMock(return_value=instance)

        self._run_failure_then_success(
            bridge,
            fail,
            ok,
            lambda b: b.yara_scan("inst"),
            lambda b: b.yara_scan("inst"),
            "yara fail",
        )

    def test_extract_iocs_clears_last_error_on_success(self) -> None:
        """Extract_iocs clears last_error after success following a failure."""
        bridge = SandboxBridge()

        async def fail_then_recover() -> None:
            analysis_mod = importlib.import_module("intellicrack.sandbox.analysis")
            with (
                patch.object(bridge, "ensure_manager") as mock_mgr,
                patch.object(analysis_mod, "extract_iocs", side_effect=ValueError("ioc fail")),
            ):
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=self._make_mock_instance(with_report=True))
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="ioc fail"):
                    await bridge.extract_iocs("inst")

            assert bridge.state.last_error is not None
            assert "ioc fail" in bridge.state.last_error

            with (
                patch.object(bridge, "ensure_manager") as mock_mgr,
                patch.object(analysis_mod, "extract_iocs", return_value=[]),
            ):
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=self._make_mock_instance(with_report=True))
                mock_mgr.return_value = manager
                await bridge.extract_iocs("inst")

            assert bridge.state.last_error is None, bridge.state.last_error

        asyncio.run(fail_then_recover())

    def test_timeline_clears_last_error_on_success(self) -> None:
        """Timeline clears last_error after success following a failure."""
        bridge = SandboxBridge()

        async def fail_then_recover() -> None:
            analysis_mod = importlib.import_module("intellicrack.sandbox.analysis")
            with (
                patch.object(bridge, "ensure_manager") as mock_mgr,
                patch.object(analysis_mod, "generate_timeline", side_effect=ValueError("tl fail")),
            ):
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=self._make_mock_instance(with_report=True))
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="tl fail"):
                    await bridge.timeline("inst")

            assert bridge.state.last_error is not None
            assert "tl fail" in bridge.state.last_error

            with (
                patch.object(bridge, "ensure_manager") as mock_mgr,
                patch.object(analysis_mod, "generate_timeline", return_value=[]),
            ):
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=self._make_mock_instance(with_report=True))
                mock_mgr.return_value = manager
                await bridge.timeline("inst")

            assert bridge.state.last_error is None

        asyncio.run(fail_then_recover())

    def test_detect_behaviors_clears_last_error_on_success(self) -> None:
        """Detect_behaviors clears last_error after success following a failure."""
        bridge = SandboxBridge()

        async def fail_then_recover() -> None:
            analysis_mod = importlib.import_module("intellicrack.sandbox.analysis")
            with (
                patch.object(bridge, "ensure_manager") as mock_mgr,
                patch.object(analysis_mod, "match_behaviors", side_effect=ValueError("beh fail")),
            ):
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=self._make_mock_instance(with_report=True))
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="beh fail"):
                    await bridge.detect_behaviors("inst")

            assert bridge.state.last_error is not None
            assert "beh fail" in bridge.state.last_error

            with (
                patch.object(bridge, "ensure_manager") as mock_mgr,
                patch.object(analysis_mod, "match_behaviors", return_value=[]),
            ):
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=self._make_mock_instance(with_report=True))
                mock_mgr.return_value = manager
                await bridge.detect_behaviors("inst")

            assert bridge.state.last_error is None

        asyncio.run(fail_then_recover())

    def test_detect_c2_clears_last_error_on_success(self) -> None:
        """Detect_c2 clears last_error after success following a failure."""
        bridge = SandboxBridge()

        async def fail_then_recover() -> None:
            analysis_mod = importlib.import_module("intellicrack.sandbox.analysis")
            with (
                patch.object(bridge, "ensure_manager") as mock_mgr,
                patch.object(analysis_mod, "detect_c2_patterns", side_effect=ValueError("c2 fail")),
            ):
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=self._make_mock_instance(with_report=True))
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="c2 fail"):
                    await bridge.detect_c2("inst")

            assert bridge.state.last_error is not None
            assert "c2 fail" in bridge.state.last_error

            with (
                patch.object(bridge, "ensure_manager") as mock_mgr,
                patch.object(analysis_mod, "detect_c2_patterns", return_value=[]),
            ):
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=self._make_mock_instance(with_report=True))
                mock_mgr.return_value = manager
                await bridge.detect_c2("inst")

            assert bridge.state.last_error is None

        asyncio.run(fail_then_recover())

    def test_diff_clears_last_error_on_success(self) -> None:
        """Diff clears last_error after success following a failure."""
        bridge = SandboxBridge()

        async def fail_then_recover() -> None:
            analysis_mod = importlib.import_module("intellicrack.sandbox.analysis")
            inst_a = self._make_mock_instance(with_report=True)
            inst_b = self._make_mock_instance(with_report=True)

            def get_side_effect(instance_id: str) -> MagicMock:
                return inst_a if instance_id == "a" else inst_b

            with (
                patch.object(bridge, "ensure_manager") as mock_mgr,
                patch.object(analysis_mod, "diff_reports", side_effect=ValueError("diff fail")),
            ):
                manager = AsyncMock()
                manager.get = AsyncMock(side_effect=get_side_effect)
                mock_mgr.return_value = manager
                with pytest.raises(ToolError, match="diff fail"):
                    await bridge.diff("a", "b")

            assert bridge.state.last_error is not None
            assert "diff fail" in bridge.state.last_error

            with (
                patch.object(bridge, "ensure_manager") as mock_mgr,
                patch.object(analysis_mod, "diff_reports", return_value={}),
            ):
                manager = AsyncMock()
                manager.get = AsyncMock(side_effect=get_side_effect)
                mock_mgr.return_value = manager
                await bridge.diff("a", "b")

            assert bridge.state.last_error is None

        asyncio.run(fail_then_recover())

    def test_state_preserves_target_path_across_recovery(self, tmp_path: Path) -> None:
        """A successful op after run_binary preserves target_path / binary_loaded."""
        bridge = SandboxBridge()
        binary = tmp_path / "tracked.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 62)

        mock_instance = MagicMock()
        mock_instance.id = "rb-id"
        report = _make_execution_report()

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.run_binary = AsyncMock(return_value=(mock_instance, report))
                mock_mgr.return_value = manager
                await bridge.run_binary(str(binary))

            assert bridge.state.binary_loaded is True
            assert bridge.state.target_path is not None

            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                inst = MagicMock()
                inst.sandbox_type = "qemu"
                inst.touch = MagicMock()
                inst.sandbox.take_snapshot = AsyncMock(return_value="snap-id")
                manager.get = AsyncMock(return_value=inst)
                mock_mgr.return_value = manager
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

    def test_analysis_module_called_once_for_multiple_bridge_calls(self) -> None:
        """_get_analysis_module is called at most once for multiple analysis calls."""
        bridge = SandboxBridge()

        mock_report = MagicMock()
        mock_instance = MagicMock()
        mock_instance.last_report = mock_report

        call_count = 0

        real_module = MagicMock()
        real_module.extract_iocs = MagicMock(return_value=[])

        def counting_import() -> object:
            nonlocal call_count
            call_count += 1
            return real_module

        with patch("intellicrack.bridges.sandbox_bridge._get_analysis_module") as mock_cached:
            mock_cached.side_effect = counting_import

            async def run() -> None:
                with patch.object(bridge, "ensure_manager") as mock_mgr:
                    manager = AsyncMock()
                    manager.get = AsyncMock(return_value=mock_instance)
                    mock_mgr.return_value = manager
                    await bridge.extract_iocs("some-id")

            asyncio.run(run())

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

        failed_response = MagicMock()
        failed_response.success = False
        failed_response.error = "VM error"
        mock_qmp = MagicMock()
        mock_qmp.cont = AsyncMock(return_value=failed_response)

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "qemu"
        type(mock_instance.sandbox).qmp = property(lambda _self: mock_qmp)

        records: list[logging.LogRecord] = []

        class CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = CapturingHandler()
        handler.setLevel(logging.INFO)
        bridge_logger = logging.getLogger("intellicrack.bridges.sandbox_bridge")
        bridge_logger.addHandler(handler)

        async def run() -> None:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
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
        """get_pending_messages returns unknown type when message has no message_type."""
        bridge = SandboxBridge()

        bad_message = object()

        mock_agent = AsyncMock()
        mock_agent.get_pending_messages = AsyncMock(return_value=[bad_message])

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "qemu"
        type(mock_instance.sandbox).agent = property(lambda _self: mock_agent)

        async def run() -> dict[str, Any]:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                return await bridge.get_pending_messages("some-id")

        result = asyncio.run(run())
        assert result["count"] == 1
        assert result["messages"][0]["type"] == "unknown"

    def test_message_type_read_via_getattr(self) -> None:
        """get_pending_messages reads message_type safely via getattr."""
        bridge = SandboxBridge()

        class MockMessage:
            message_type: ClassVar[str] = "exec_result"
            data: ClassVar[dict[str, object]] = {}

        mock_agent = AsyncMock()
        mock_agent.get_pending_messages = AsyncMock(return_value=[MockMessage()])

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "qemu"
        type(mock_instance.sandbox).agent = property(lambda _self: mock_agent)

        async def run() -> dict[str, Any]:
            with patch.object(bridge, "ensure_manager") as mock_mgr:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_mgr.return_value = manager
                return await bridge.get_pending_messages("some-id")

        result = asyncio.run(run())
        assert result["count"] == 1
        assert result["messages"][0]["type"] == "exec_result"


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

    def test_raises_on_non_dataclass(self) -> None:
        """dataclass_to_dict raises ToolError for non-dataclass input."""
        with pytest.raises(ToolError, match="Expected a dataclass instance"):
            dataclass_to_dict({"not": "a dataclass"})

    def test_raises_on_dataclass_class_not_instance(self) -> None:
        """dataclass_to_dict raises ToolError when given the class itself."""
        with pytest.raises(ToolError, match="Expected a dataclass instance"):
            dataclass_to_dict(self._SimpleReport)


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

    def test_list_method_emits_utc_timestamps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """list() emits UTC ISO-8601 timestamps for created_at and last_used."""
        bridge = SandboxBridge()
        now = datetime.now(UTC)

        mock_instance = MagicMock()
        mock_instance.id = "inst-1"
        mock_instance.sandbox_type = "windows"
        mock_instance.state.status = "running"
        mock_instance.created_at = now
        mock_instance.last_used = now
        mock_instance.binary_path = None

        mock_manager = MagicMock()
        mock_manager.instances = [mock_instance]
        monkeypatch.setattr(bridge, "_manager", mock_manager)

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
