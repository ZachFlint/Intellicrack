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

The matching-profile case is exercised on a Linux guest. A Linux guest has no
guest-side hardening step, so the only techniques are the launch-time SMBIOS
and CPUID arguments - exactly what this test asserts - and the call succeeds
without an agent. On a Windows guest the same launch-time-only result would now
be a failure, because S17-D77 makes ``apply_anti_evasion`` refuse to report a
clean success when guest-side hardening was expected but never ran.
"""

from __future__ import annotations

import asyncio
from typing import Any, Literal, cast
from unittest.mock import MagicMock

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
)


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

    def set_qemu_config(self, cfg: QEMUConfig) -> None:
        """Override the QEMU config for tests.

        Args:
            cfg: QEMUConfig to install.
        """
        self._qemu_config = cfg


def _make_sandbox(
    *,
    anti_evasion_profile: Literal["default", "workstation", "laptop"],
    guest_os: GuestOS = GuestOS.WINDOWS,
) -> _AntiEvasionTestSandbox:
    """Construct a sandbox in ``running`` state with a stubbed QMP and no agent.

    The agent is deliberately left unset. On a Linux guest that is the whole
    guest-side story - there is none - so the call reports only launch-time
    techniques and succeeds. On a Windows guest with no agent the call now
    fails, which is what the mismatched-profile scenario relies on: its
    ``SandboxError`` must come from the profile check, so it is raised before
    the guest-side path is ever reached.

    Args:
        anti_evasion_profile: Profile to set on :class:`QEMUConfig`. Restricted
            to the literal set accepted by :class:`QEMUConfig`.
        guest_os: Guest OS to launch the sandbox as.

    Returns:
        _AntiEvasionTestSandbox: Sandbox ready for ``apply_anti_evasion``.
    """
    cfg = QEMUConfig(guest_os=guest_os, anti_evasion_profile=anti_evasion_profile)
    sb = _AntiEvasionTestSandbox(config=SandboxConfig(), qemu_config=cfg)
    sb.set_accelerator(AcceleratorType.TCG)
    sb.state.status = "running"
    sb.set_qmp(MagicMock())
    return sb


class TestF0029AntiEvasionProfileHonoured:
    """F-0029: apply_anti_evasion must honour the ``profile`` argument."""

    def test_matching_profile_returns_success_with_actual_config_techniques(self) -> None:
        """Scenario A: matching profile succeeds and reports real techniques.

        Given a Linux sandbox launched with ``anti_evasion_profile='default'``
        and a caller passing ``profile='default'``, the method must succeed and
        the reported launch-time techniques (SMBIOS types, CPUID mask) must
        correspond to the frozen audit-specified SMBIOS type numbers. A Linux
        guest has no guest-side hardening step, so the launch-time arguments are
        the whole result and the call succeeds without an agent.

        The independent oracle is the frozen set ``{"1", "2", "3"}``: the three
        SMBIOS table types that ``_anti_evasion_smbios_entries`` must emit for
        every profile (system, baseboard, chassis).  It is hand-maintained and
        kept separate from any production helper so a regression in
        ``_anti_evasion_smbios_entries`` cannot regress the expected value in
        lockstep.

        Mutation proof: deleting the type-2 entry from the ``default`` branch of
        ``_anti_evasion_smbios_entries`` (e.g. returning only types ``"1"`` and
        ``"3"``) changes ``reported_smbios_types`` to ``{"1", "3"}`` which
        differs from the frozen ``{"1", "2", "3"}`` oracle and fails this test.
        """
        frozen_default_smbios_types: frozenset[str] = frozenset({"1", "2", "3"})
        frozen_launch_techniques: list[str] = [
            "smbios_type_1_launch_arg",
            "smbios_type_2_launch_arg",
            "smbios_type_3_launch_arg",
            "cpuid_hypervisor_mask_launch_arg",
        ]

        sb = _make_sandbox(anti_evasion_profile="default", guest_os=GuestOS.LINUX)

        result: dict[str, Any] = asyncio.run(sb.apply_anti_evasion(profile="default"))

        assert result["profile"] == "default", f"result['profile'] must be 'default', got {result['profile']!r}"
        raw_techniques: object = result["techniques"]
        assert isinstance(raw_techniques, list)
        techniques: list[str] = []
        for raw in cast("list[object]", raw_techniques):
            assert isinstance(raw, str)
            techniques.append(raw)

        assert "cpuid_hypervisor_mask_launch_arg" in techniques, (
            "cpuid_hypervisor_mask_launch_arg must be present in launch-time techniques"
        )

        reported_smbios_types: frozenset[str] = frozenset(
            t.removeprefix("smbios_type_").removesuffix("_launch_arg")
            for t in techniques
            if t.startswith("smbios_type_") and t.endswith("_launch_arg")
        )
        assert reported_smbios_types == frozen_default_smbios_types, (
            f"SMBIOS type numbers must be exactly {sorted(frozen_default_smbios_types)!r} "
            f"(frozen audit oracle); got {sorted(reported_smbios_types)!r}"
        )

        assert techniques == frozen_launch_techniques, (
            f"launch-time techniques (agent disconnected) must be exactly {frozen_launch_techniques!r}; got {techniques!r}"
        )

        assert result["count"] == len(techniques), f"count {result['count']!r} must equal len(techniques) {len(techniques)}"

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
