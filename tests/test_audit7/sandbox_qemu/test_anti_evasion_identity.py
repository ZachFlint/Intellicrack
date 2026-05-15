# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Regression tests for audit7 F-0022 and F-0029.

These two findings share :func:`QEMUSandbox.apply_anti_evasion` and must be
verified together because each individual fix is meaningless without the
other:

* **F-0022 (reg.exe allowlist miss).** ``apply_anti_evasion`` previously
  dispatched ``reg.exe`` to the guest agent as a bare command name. The
  Windows agent's ``Test-AllowedCommand`` allowlist accepts only entries in
  ``allowedNames`` (``powershell``, ``powershell.exe``, ``cmd``, ``cmd.exe``)
  or absolute ``.exe`` paths rooted at ``Z:\``, ``%SystemRoot%\System32\``,
  or ``%SystemRoot%\SysWOW64\``. Bare ``reg.exe`` matched no rule, so every
  registry patch silently failed with ``exit_code=-1``.
* **F-0029 (profile vs hardcoded HP identity).** The SMBIOS launch arguments
  switched manufacturer/product strings on the
  ``QEMUConfig.anti_evasion_profile`` field, but the registry writes
  unconditionally advertised ``"HP"`` and ``"HP EliteDesk 800 G6"``. With a
  ``workstation`` profile the SMBIOS reported Dell while the registry (once
  F-0022 is fixed) wrote HP, a trivially detectable inconsistency.

The fixes consume a single :func:`QEMUSandbox._anti_evasion_identity` helper
in both code paths and pass the absolute ``C:\Windows\System32\reg.exe``
path to every ``reg.exe`` invocation. These tests pin both behaviours.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Literal, cast
from unittest.mock import MagicMock

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import (
    WINDOWS_REG_EXE_PATH,
    AcceleratorType,
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
)
from tests._helpers.guest_allowlist import is_windows_allowlisted


if TYPE_CHECKING:
    from collections.abc import Sequence


class _AntiEvasionTestSandbox(QEMUSandbox):
    """``QEMUSandbox`` subclass exposing test-only state setters.

    Keeps ``basedpyright`` ``reportPrivateUsage`` satisfied by performing
    private-attribute mutation from inside the class hierarchy.
    """

    def set_accelerator(self, accel: AcceleratorType) -> None:
        """Pre-populate the accelerator cache so no real detection runs.

        Args:
            accel: Accelerator type to record as cached.
        """
        self._accelerator = accel
        self._accelerator_cached = True

    def set_qmp(self, qmp: object) -> None:
        """Override the QMP client for tests.

        Args:
            qmp: Duck-typed QMP client. ``MagicMock`` is sufficient because
                ``apply_anti_evasion`` only checks ``self._qmp is not None``.
        """
        setattr(self, "_qmp", qmp)

    def set_agent(self, agent: GuestAgentClient | None) -> None:
        """Override the guest agent client.

        Args:
            agent: Agent instance, or ``None`` to disable the agent path.
        """
        self._agent = agent

    def set_qemu_config(self, cfg: QEMUConfig) -> None:
        """Override the QEMU config for tests.

        Args:
            cfg: ``QEMUConfig`` instance to install.
        """
        self._qemu_config = cfg

    @staticmethod
    def identity_for_test(profile: str) -> tuple[str, str]:
        """Expose ``_anti_evasion_identity`` for cross-class assertion.

        Args:
            profile: Anti-evasion profile name.

        Returns:
            tuple[str, str]: ``(manufacturer, product)`` pair produced for
            ``profile``.
        """
        return QEMUSandbox._anti_evasion_identity(profile)

    @staticmethod
    def smbios_entries_for_test(profile: str) -> list[dict[str, str]]:
        """Expose ``_anti_evasion_smbios_entries`` for cross-class assertion.

        Args:
            profile: Anti-evasion profile name.

        Returns:
            list[dict[str, str]]: SMBIOS entry dicts produced for ``profile``.
        """
        return QEMUSandbox._anti_evasion_smbios_entries(profile)

    @staticmethod
    def windows_reg_exe_path_for_test() -> str:
        """Expose the ``WINDOWS_REG_EXE_PATH`` module constant.

        Returns:
            str: Absolute Windows path that ``apply_anti_evasion`` dispatches as
            the executable for every registry patch.
        """
        return WINDOWS_REG_EXE_PATH


class _RecordingAgent(GuestAgentClient):
    """``GuestAgentClient`` subclass that records every ``send_command`` call.

    The agent reports as connected, replicates the in-guest allowlist
    decision, and returns ``exit_code=0`` only for accepted commands. The
    recorded ``(command, args)`` list lets tests assert that every dispatched
    executable uses an allowlist-safe absolute path.

    Attributes:
        sent_commands: Ordered list of ``(command, args)`` tuples observed.
    """

    sent_commands: list[tuple[str, list[str]]]

    def __init__(self) -> None:
        """Initialise the agent in a connected state without opening a socket."""
        super().__init__(host="127.0.0.1", port=4445)
        self.connected = True
        self.sent_commands = []

    async def connect(self, time_limit: float = 60.0, retry_interval: float = 2.0) -> bool:
        """No-op connect that keeps the agent flagged as connected.

        Args:
            time_limit: Ignored.
            retry_interval: Ignored.

        Returns:
            bool: Always ``True``.
        """
        del time_limit, retry_interval
        return True

    async def disconnect(self) -> None:
        """Flag the agent as disconnected without touching any socket."""
        self.connected = False

    async def send_command(
        self,
        command: str,
        args: Sequence[str] | None = None,
        time_limit: float = 30.0,
    ) -> tuple[int, str, str]:
        """Record the dispatch and emulate ``Test-AllowedCommand`` semantics.

        Args:
            command: Command name or absolute path the sandbox dispatched.
            args: Argument list (recorded verbatim).
            time_limit: Ignored; the in-process emulation is instant.

        Returns:
            tuple[int, str, str]: ``(exit_code, stdout, stderr)`` with
            ``exit_code=0`` when ``command`` would pass the agent allowlist
            and ``exit_code=-1`` with the agent's error string otherwise.
        """
        del time_limit
        arg_list: list[str] = list(args) if args else []
        self.sent_commands.append((command, arg_list))
        if is_windows_allowlisted(command):
            return (0, "", "")
        return (-1, "", f"command not in allowlist: {command}")


def _make_sandbox(
    *,
    anti_evasion_profile: Literal["default", "workstation", "laptop"],
    agent: GuestAgentClient | None,
) -> _AntiEvasionTestSandbox:
    """Construct a running sandbox with a stubbed QMP and the supplied agent.

    Args:
        anti_evasion_profile: Profile to set on :class:`QEMUConfig`.
        agent: Guest agent to install, or ``None`` to skip the agent path.

    Returns:
        _AntiEvasionTestSandbox: Sandbox ready for ``apply_anti_evasion``.
    """
    cfg = QEMUConfig(guest_os=GuestOS.WINDOWS, anti_evasion_profile=anti_evasion_profile)
    sb = _AntiEvasionTestSandbox(config=SandboxConfig(), qemu_config=cfg)
    sb.set_accelerator(AcceleratorType.TCG)
    sb.state.status = "running"
    sb.set_qmp(MagicMock())
    sb.set_agent(agent)
    return sb


class TestF0022RegExeAllowlistSafe:
    """F-0022: every ``reg.exe`` invocation must satisfy ``Test-AllowedCommand``."""

    def test_resolved_reg_exe_path_is_allowlist_safe(self) -> None:
        """The path constant baked into ``apply_anti_evasion`` is itself accepted.

        This guards the constant against a refactor that drops the absolute
        prefix; ``Test-AllowedCommand`` must return ``True`` for the resolved
        value.
        """
        reg_exe_path = _AntiEvasionTestSandbox.windows_reg_exe_path_for_test()
        assert is_windows_allowlisted(reg_exe_path), (
            f"reg.exe path constant {reg_exe_path!r} is rejected by Test-AllowedCommand "
            "emulation; the audit's allowlist regression would still trigger"
        )

    def test_bare_reg_exe_would_be_rejected(self) -> None:
        """Sanity-check: a bare ``reg.exe`` is rejected by the allowlist emulation.

        This is the pre-fix dispatch value. If this test ever passed for the
        bare string, the allowlist emulation would be wrong and downstream
        tests could not detect the original defect.
        """
        assert not is_windows_allowlisted("reg.exe"), (
            "bare 'reg.exe' must be rejected by Test-AllowedCommand emulation; otherwise the "
            "regression assertion below provides no protection"
        )

    def test_apply_anti_evasion_dispatches_only_allowlisted_commands(self) -> None:
        """Every dispatched executable must pass the allowlist emulation.

        Drives ``apply_anti_evasion`` against a connected recording agent and
        asserts that none of the recorded ``(command, args)`` dispatches use
        a bare ``reg.exe`` and that every command satisfies the in-guest
        ``Test-AllowedCommand`` rule.
        """
        agent = _RecordingAgent()
        sb = _make_sandbox(anti_evasion_profile="default", agent=agent)

        asyncio.run(sb.apply_anti_evasion(profile="default"))

        assert agent.sent_commands, "apply_anti_evasion did not dispatch any agent commands"
        for command, _args in agent.sent_commands:
            assert command != "reg.exe", (
                "apply_anti_evasion dispatched bare 'reg.exe'; the allowlist will reject it and the "
                "registry patch silently fails (F-0022 regression)"
            )
            assert is_windows_allowlisted(command), f"command {command!r} would be rejected by the in-guest allowlist"

    def test_apply_anti_evasion_records_registry_patch_techniques(self) -> None:
        """All four registry patches must succeed when the agent accepts them.

        With the F-0022 fix the agent returns ``exit_code=0`` for each
        ``reg.exe`` dispatch, so the returned ``techniques`` list must
        contain four ``registry_patch`` entries (one per registry command).
        Pre-fix every dispatch returned ``-1`` and no ``registry_patch``
        entries were recorded.
        """
        agent = _RecordingAgent()
        sb = _make_sandbox(anti_evasion_profile="default", agent=agent)

        result: dict[str, Any] = asyncio.run(sb.apply_anti_evasion(profile="default"))

        raw_techniques: object = result["techniques"]
        assert isinstance(raw_techniques, list)
        techniques: list[str] = []
        for raw in cast("list[object]", raw_techniques):
            assert isinstance(raw, str)
            techniques.append(raw)
        registry_patch_count = sum(1 for t in techniques if t == "registry_patch")
        assert registry_patch_count == 4, (
            f"expected 4 registry_patch techniques (one per reg.exe dispatch); got {registry_patch_count} from techniques={techniques!r}"
        )


class TestF0029IdentityProfileConsistency:
    """F-0029: SMBIOS and registry identity strings must agree per profile."""

    @pytest.mark.parametrize(
        ("profile", "expected_manufacturer", "expected_product"),
        [
            ("default", "HP", "HP EliteDesk 800 G6"),
            ("workstation", "Dell Inc.", "OptiPlex 7090"),
            ("laptop", "Lenovo", "ThinkPad T14 Gen 3"),
        ],
    )
    def test_identity_helper_returns_expected_tuple(
        self,
        profile: str,
        expected_manufacturer: str,
        expected_product: str,
    ) -> None:
        """``_anti_evasion_identity`` returns the documented per-profile pair.

        Args:
            profile: Anti-evasion profile name.
            expected_manufacturer: Manufacturer string the helper must return.
            expected_product: Product string the helper must return.
        """
        manufacturer, product = _AntiEvasionTestSandbox.identity_for_test(profile)
        assert manufacturer == expected_manufacturer
        assert product == expected_product

    @pytest.mark.parametrize("profile", ["default", "workstation", "laptop"])
    def test_smbios_type1_matches_identity_helper(self, profile: str) -> None:
        """SMBIOS type-1 entry mirrors :func:`_anti_evasion_identity`.

        Type-1 carries the system manufacturer and product strings reported
        by ``Win32_ComputerSystem`` / ``Win32_ComputerSystemProduct``. They
        must match the registry writes performed later in
        ``apply_anti_evasion`` for the same profile.

        Args:
            profile: Anti-evasion profile name.
        """
        manufacturer, product = _AntiEvasionTestSandbox.identity_for_test(profile)
        entries = _AntiEvasionTestSandbox.smbios_entries_for_test(profile)
        type1_entries = [e for e in entries if e.get("type") == "1"]
        assert len(type1_entries) == 1, f"expected exactly one SMBIOS type-1 entry, got {type1_entries!r}"
        type1 = type1_entries[0]
        assert type1["manufacturer"] == manufacturer
        assert type1["product"] == product

    @pytest.mark.parametrize(
        "profile",
        ["default", "workstation", "laptop"],
    )
    def test_registry_writes_use_profile_identity(self, profile: Literal["default", "workstation", "laptop"]) -> None:
        """Registry ``SystemManufacturer`` / ``SystemProductName`` track the profile.

        Drives ``apply_anti_evasion`` with a connected recording agent for
        each supported profile and asserts that the ``reg.exe`` arguments
        contain the manufacturer and product strings returned by
        ``_anti_evasion_identity`` -- never the hardcoded ``"HP"`` pair the
        pre-fix code emitted for non-default profiles.

        Args:
            profile: Anti-evasion profile to launch the sandbox with.
        """
        agent = _RecordingAgent()
        sb = _make_sandbox(anti_evasion_profile=profile, agent=agent)

        asyncio.run(sb.apply_anti_evasion(profile=profile))

        expected_manufacturer, expected_product = _AntiEvasionTestSandbox.identity_for_test(profile)
        manufacturer_args: list[list[str]] = []
        product_args: list[list[str]] = []
        for _cmd, args in agent.sent_commands:
            if "SystemManufacturer" in args:
                manufacturer_args.append(args)
            elif "SystemProductName" in args:
                product_args.append(args)

        assert len(manufacturer_args) == 1, f"expected one SystemManufacturer write, got {manufacturer_args!r}"
        assert len(product_args) == 1, f"expected one SystemProductName write, got {product_args!r}"

        # The /d value is the argument immediately after "/d" in reg.exe argv.
        def _value_for(argv: list[str]) -> str:
            """Extract the ``/d`` value from a ``reg.exe add`` argument list.

            Args:
                argv: Argument list passed to ``reg.exe``.

            Returns:
                str: The value following the ``/d`` flag.
            """
            return argv[argv.index("/d") + 1]

        manufacturer_value = _value_for(manufacturer_args[0])
        product_value = _value_for(product_args[0])

        assert manufacturer_value == expected_manufacturer, (
            f"profile={profile!r}: registry SystemManufacturer is {manufacturer_value!r} but SMBIOS-driven "
            f"identity is {expected_manufacturer!r}; sandbox would advertise inconsistent vendors (F-0029)"
        )
        assert product_value == expected_product, (
            f"profile={profile!r}: registry SystemProductName is {product_value!r} but SMBIOS-driven "
            f"identity is {expected_product!r}; sandbox would advertise inconsistent products (F-0029)"
        )

    def test_switching_profiles_yields_consistent_strings_everywhere(self) -> None:
        """Independently switching profiles keeps SMBIOS and registry in sync.

        Iterates over all supported profiles, captures both the SMBIOS
        identity and the registry-dispatch identity, and asserts they agree
        with each other and with the helper for every profile. The pre-fix
        code passed this assertion only for ``default``.
        """
        profiles: tuple[Literal["default", "workstation", "laptop"], ...] = ("default", "workstation", "laptop")
        for profile in profiles:
            agent = _RecordingAgent()
            sb = _make_sandbox(anti_evasion_profile=profile, agent=agent)

            asyncio.run(sb.apply_anti_evasion(profile=profile))

            smbios_entries = _AntiEvasionTestSandbox.smbios_entries_for_test(profile)
            type1 = next(e for e in smbios_entries if e.get("type") == "1")
            smbios_manufacturer = type1["manufacturer"]
            smbios_product = type1["product"]

            manufacturer_args = next(args for _cmd, args in agent.sent_commands if "SystemManufacturer" in args)
            product_args = next(args for _cmd, args in agent.sent_commands if "SystemProductName" in args)
            registry_manufacturer = manufacturer_args[manufacturer_args.index("/d") + 1]
            registry_product = product_args[product_args.index("/d") + 1]

            assert smbios_manufacturer == registry_manufacturer, (
                f"profile={profile!r}: SMBIOS manufacturer {smbios_manufacturer!r} differs from registry "
                f"manufacturer {registry_manufacturer!r}; trivially detectable inconsistency"
            )
            assert smbios_product == registry_product, (
                f"profile={profile!r}: SMBIOS product {smbios_product!r} differs from registry product "
                f"{registry_product!r}; trivially detectable inconsistency"
            )
