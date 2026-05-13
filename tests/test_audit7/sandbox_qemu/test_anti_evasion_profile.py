# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit7 F-0029: apply_anti_evasion honours profile param.

The pre-fix code silently accepted any ``profile`` string and reported it back
in the result dict while applying whichever launch-time profile QEMUConfig was
constructed with. These tests verify that:

* When ``profile`` matches the launch-time profile, the call succeeds and the
  reported techniques are sourced from the actual config.
* When ``profile`` differs, the call raises :class:`SandboxError` with a clear
  message containing both profile names, rather than silently returning a
  misleading success payload.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Literal, cast
from unittest.mock import MagicMock

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
)


if TYPE_CHECKING:
    from collections.abc import Sequence


class _AntiEvasionTestSandbox(QEMUSandbox):
    """QEMUSandbox subclass exposing internal state setters for tests.

    Mirrors the pattern used in ``tests/test_audit4/a3_qemu_sandbox`` so that
    we can drive ``apply_anti_evasion`` without launching a real QEMU process.
    """

    def set_accelerator(self, accel: AcceleratorType) -> None:
        """Set the cached accelerator type for tests.

        Args:
            accel: Accelerator type to cache.
        """
        self._accelerator = accel
        self._accelerator_cached = True

    def set_qmp(self, qmp: object) -> None:
        """Set the QMP client for tests.

        Args:
            qmp: Duck-typed QMP client (allows MagicMock for the success path).
        """
        setattr(self, "_qmp", qmp)

    def set_agent(self, agent: GuestAgentClient | None) -> None:
        """Set the guest agent client for tests.

        Args:
            agent: Guest agent client or None to disable the agent path.
        """
        self._agent = agent

    def set_qemu_config(self, cfg: QEMUConfig) -> None:
        """Override the QEMU config for tests.

        Args:
            cfg: QEMUConfig to install.
        """
        self._qemu_config = cfg

    @staticmethod
    def smbios_entries_for_test(profile: str) -> list[dict[str, str]]:
        """Expose ``_anti_evasion_smbios_entries`` for cross-class assertion.

        Args:
            profile: Anti-evasion profile name.

        Returns:
            list[dict[str, str]]: SMBIOS entry dicts produced for ``profile``.
        """
        return QEMUSandbox._anti_evasion_smbios_entries(profile)


class _DisconnectedAgent(GuestAgentClient):
    """GuestAgentClient that reports as disconnected without performing I/O.

    Causes :meth:`QEMUSandbox.apply_anti_evasion` to skip the agent-side
    registry-patch branch, leaving only the launch-time technique reporting
    so the test can assert profile-driven SMBIOS/CPUID entries without
    stubbing every reg.exe / PowerShell call.
    """

    def __init__(self) -> None:
        """Initialise the disconnected agent without opening a socket."""
        super().__init__(host="127.0.0.1", port=4445)
        self.connected = False

    async def connect(self, time_limit: float = 60.0, retry_interval: float = 2.0) -> bool:
        """Return False without attempting to connect.

        Args:
            time_limit: Ignored.
            retry_interval: Ignored.

        Returns:
            bool: Always False; agent stays disconnected.
        """
        del time_limit, retry_interval
        return False

    async def disconnect(self) -> None:
        """No-op disconnect for the disconnected agent."""
        self.connected = False

    async def send_command(
        self,
        command: str,
        args: Sequence[str] | None = None,
        time_limit: float = 30.0,
    ) -> tuple[int, str, str]:
        """Fail the call to detect any accidental invocation in tests.

        Args:
            command: Command name (ignored).
            args: Optional argument list (ignored).
            time_limit: Timeout in seconds (ignored).

        Returns:
            tuple[int, str, str]: Never returns; always raises.

        Raises:
            AssertionError: Always; the test must not reach this path.
        """
        del command, args, time_limit
        msg = "send_command must not be invoked when the agent is disconnected"
        raise AssertionError(msg)


def _make_sandbox(*, anti_evasion_profile: Literal["default", "workstation", "laptop"]) -> _AntiEvasionTestSandbox:
    """Construct a sandbox in ``running`` state with a stubbed QMP and agent.

    Args:
        anti_evasion_profile: Profile to set on :class:`QEMUConfig`. Restricted
            to the literal set accepted by :class:`QEMUConfig`.

    Returns:
        _AntiEvasionTestSandbox: Sandbox ready for ``apply_anti_evasion``
        invocation with the agent path disabled.
    """
    cfg = QEMUConfig(guest_os=GuestOS.WINDOWS, anti_evasion_profile=anti_evasion_profile)
    sb = _AntiEvasionTestSandbox(config=SandboxConfig(), qemu_config=cfg)
    sb.set_accelerator(AcceleratorType.TCG)
    sb.state.status = "running"
    sb.set_qmp(MagicMock())
    sb.set_agent(_DisconnectedAgent())
    return sb


class TestF0029AntiEvasionProfileHonoured:
    """F-0029: apply_anti_evasion must honour the ``profile`` argument."""

    def test_matching_profile_returns_success_with_actual_config_techniques(self) -> None:
        """Scenario A: matching profile succeeds and reports real techniques.

        Given a sandbox launched with ``anti_evasion_profile='default'`` and a
        caller passing ``profile='default'``, the method must succeed and the
        reported launch-time techniques (SMBIOS types, CPUID mask) must
        correspond to the actual config-driven SMBIOS entries.
        """
        sb = _make_sandbox(anti_evasion_profile="default")

        result: dict[str, Any] = asyncio.run(sb.apply_anti_evasion(profile="default"))

        assert result["profile"] == "default"
        raw_techniques: object = result["techniques"]
        assert isinstance(raw_techniques, list)
        techniques: list[str] = []
        for raw in cast("list[object]", raw_techniques):
            assert isinstance(raw, str)
            techniques.append(raw)
        assert "cpuid_hypervisor_mask_launch_arg" in techniques
        expected_smbios_types: set[str] = {entry["type"] for entry in _AntiEvasionTestSandbox.smbios_entries_for_test("default")}
        reported_smbios_types: set[str] = {
            t.removeprefix("smbios_type_").removesuffix("_launch_arg")
            for t in techniques
            if t.startswith("smbios_type_") and t.endswith("_launch_arg")
        }
        assert reported_smbios_types == expected_smbios_types
        assert result["count"] == len(techniques)

    def test_mismatched_profile_raises_sandbox_error_with_both_names(self) -> None:
        """Scenario B: mismatched profile raises SandboxError.

        Given a sandbox launched with ``anti_evasion_profile='default'`` and a
        caller passing ``profile='hardened'``, the method must raise
        :class:`SandboxError` whose message contains both profile names.
        Silently returning ``success=True`` (the pre-fix behaviour) is wrong
        because SMBIOS/CPUID masking cannot be re-applied post-launch.
        """
        sb = _make_sandbox(anti_evasion_profile="default")

        with pytest.raises(SandboxError) as exc_info:
            asyncio.run(sb.apply_anti_evasion(profile="hardened"))

        message = str(exc_info.value)
        assert "hardened" in message, f"requested profile name missing from error: {message!r}"
        assert "default" in message, f"current launch-time profile name missing from error: {message!r}"
