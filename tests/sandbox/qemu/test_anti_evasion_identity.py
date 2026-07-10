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

The oracle for these tests is :data:`_EXPECTED_IDENTITY`, an independent,
hand-maintained specification of the per-profile manufacturer/product strings
the audit requires. It is **not** derived from the production helper; it is the
contract the production code must satisfy. Every assertion threads a single,
independently-known identity through the whole production chain and checks the
two consumers agree with the spec and with each other:

* the actual ``-smbios`` launch argument string emitted by the real
  :meth:`QEMUSandbox._build_qemu_command` (the command the VM boots with), and
* the actual ``reg.exe /d`` registry value dispatched through the guest agent
  by :meth:`QEMUSandbox.apply_anti_evasion`.

If either consumer drifts from the spec, or from the other, the chain breaks
and the corresponding test fails.
"""

from __future__ import annotations

import asyncio
from pathlib import PureWindowsPath
from typing import TYPE_CHECKING, Any, Final, Literal, cast

import pytest

from intellicrack.core.types import SandboxError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import (
    WINDOWS_REG_EXE_PATH,
    AcceleratorType,
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
    QMPClient,
)
from tests._helpers.guest_allowlist import is_windows_allowlisted


if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


ProfileName = Literal["default", "workstation", "laptop"]

_EXPECTED_IDENTITY: Final[dict[ProfileName, tuple[str, str]]] = {
    "default": ("HP", "HP EliteDesk 800 G6"),
    "workstation": ("Dell Inc.", "OptiPlex 7090"),
    "laptop": ("Lenovo", "ThinkPad T14 Gen 3"),
}
"""Independent F-0029 oracle: required ``(manufacturer, product)`` per profile.

Hand-maintained to mirror the audit requirement, deliberately kept separate
from the production ``_anti_evasion_identity`` mapping so a regression in the
implementation cannot regress the expected value in lockstep.
"""

_ALL_PROFILES: Final[tuple[ProfileName, ...]] = ("default", "workstation", "laptop")

_EXPECTED_LAUNCH_TECHNIQUES: Final[list[str]] = [
    "smbios_type_1_launch_arg",
    "smbios_type_2_launch_arg",
    "smbios_type_3_launch_arg",
    "cpuid_hypervisor_mask_launch_arg",
]
"""Launch-time techniques every profile reports independent of the guest agent."""


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

    def set_unconnected_qmp(self) -> None:
        """Install a real, unconnected :class:`QMPClient`.

        ``apply_anti_evasion`` only checks ``self._qmp is not None``; a freshly
        constructed client opens no socket (``connected`` is ``False`` and no
        reader/writer exist), so this is a real production object rather than a
        fake double.
        """
        self._qmp = QMPClient(port=self._qemu_config.monitor_port)

    def clear_qmp(self) -> None:
        """Force the QMP client to ``None`` to exercise the error path."""
        self._qmp = None

    def set_agent(self, agent: GuestAgentClient | None) -> None:
        """Override the guest agent client.

        Args:
            agent: Agent instance, or ``None`` to disable the agent path.
        """
        self._agent = agent

    def set_qemu_path(self, qemu_path: Path) -> None:
        """Install the resolved QEMU binary path for command building.

        Args:
            qemu_path: Path recorded as the resolved QEMU executable.
        """
        self._qemu_path = qemu_path

    def build_command_for_test(self) -> list[str]:
        """Build the full QEMU launch command line.

        Returns:
            list[str]: The argv :meth:`_build_qemu_command` would launch QEMU
            with, including every ``-smbios`` anti-evasion entry.
        """
        return asyncio.run(self._build_qemu_command())


class _RecordingAgent(GuestAgentClient):
    """``GuestAgentClient`` subclass that records every ``send_command`` call.

    The agent reports as connected, replicates the in-guest allowlist
    decision, and returns ``exit_code=0`` only for accepted commands. The
    recorded ``(command, args)`` list lets tests assert that every dispatched
    executable uses an allowlist-safe absolute path and carries the correct
    profile identity.

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
    anti_evasion_profile: ProfileName,
    agent: GuestAgentClient | None,
    image_path: Path | None = None,
) -> _AntiEvasionTestSandbox:
    """Construct a running sandbox with a real unconnected QMP and the agent.

    Args:
        anti_evasion_profile: Profile to set on :class:`QEMUConfig`.
        agent: Guest agent to install, or ``None`` to skip the agent path.
        image_path: Optional disk-image path recorded on the config so the
            real :meth:`_build_qemu_command` can run.

    Returns:
        _AntiEvasionTestSandbox: Sandbox ready for ``apply_anti_evasion``.
    """
    cfg = QEMUConfig(guest_os=GuestOS.WINDOWS, anti_evasion_profile=anti_evasion_profile, image_path=image_path)
    sb = _AntiEvasionTestSandbox(config=SandboxConfig(), qemu_config=cfg)
    sb.set_accelerator(AcceleratorType.TCG)
    sb.state.status = "running"
    sb.set_unconnected_qmp()
    sb.set_agent(agent)
    return sb


def _reg_value_for(argv: list[str]) -> str:
    """Return the ``/d`` data value from a ``reg.exe add`` argument list.

    Args:
        argv: Argument list passed to ``reg.exe``.

    Returns:
        str: The value following the ``/d`` flag. The lookup asserts the flag
        and a following value are present so a malformed argv fails loudly.
    """
    assert "/d" in argv, f"reg.exe argv {argv!r} has no /d data flag"
    idx = argv.index("/d")
    assert idx + 1 < len(argv), f"reg.exe argv {argv!r} has /d with no following value"
    return argv[idx + 1]


def _smbios_type1_identity_from_launch_cmd(cmd: list[str]) -> tuple[str, str]:
    """Extract ``(manufacturer, product)`` from the ``-smbios`` type-1 launch arg.

    Parses the real QEMU command line produced by ``_build_qemu_command``,
    finds the single ``type=1`` ``-smbios`` value, and decodes its
    comma-separated ``key=value`` pairs. This is an oracle independent of the
    identity helper: it inspects the literal string the VM would boot with.

    Args:
        cmd: Full QEMU argv as built by ``_build_qemu_command``.

    Returns:
        tuple[str, str]: ``(manufacturer, product)`` carried by the type-1
        SMBIOS entry. The parse asserts exactly one type-1 entry exists and it
        carries both fields, so a malformed launch command fails loudly.
    """
    type1_values: list[str] = []
    for i, arg in enumerate(cmd):
        if arg == "-smbios" and i + 1 < len(cmd):
            value = cmd[i + 1]
            fields = dict(pair.split("=", 1) for pair in value.split(",") if "=" in pair)
            if fields.get("type") == "1":
                type1_values.append(value)
    assert len(type1_values) == 1, f"expected exactly one -smbios type=1 entry in launch cmd, got {type1_values!r}"
    fields = dict(pair.split("=", 1) for pair in type1_values[0].split(",") if "=" in pair)
    assert "manufacturer" in fields, f"type-1 SMBIOS entry {type1_values[0]!r} has no manufacturer"
    assert "product" in fields, f"type-1 SMBIOS entry {type1_values[0]!r} has no product"
    return fields["manufacturer"], fields["product"]


def _make_disk_image(tmp_path: Path) -> Path:
    """Create a real, minimal qcow2 file so ``_build_qemu_command`` accepts it.

    ``_build_qemu_command`` only requires the configured image path to exist on
    disk; it does not parse the image. A valid qcow2 v3 header is written so the
    fixture is a genuine (if empty) qcow2 file rather than arbitrary bytes.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Path: Path to the created qcow2 image file.
    """
    qcow2_magic = b"QFI\xfb"
    version = (3).to_bytes(4, "big")
    header = qcow2_magic + version + bytes(64)
    image = tmp_path / "disk.qcow2"
    image.write_bytes(header)
    return image


def _make_qemu_binary(tmp_path: Path) -> Path:
    """Create a placeholder QEMU binary path on disk for command building.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Path: Path recorded as the resolved QEMU executable.
    """
    binary = tmp_path / "qemu-system-x86_64.exe"
    binary.write_bytes(b"MZ")
    return binary


class TestF0022RegExeAllowlistSafe:
    """F-0022: every ``reg.exe`` invocation must satisfy ``Test-AllowedCommand``."""

    def test_production_reg_exe_constant_equals_canonical_system32_path(self) -> None:
        r"""Pin ``WINDOWS_REG_EXE_PATH`` to the exact canonical System32 ``reg.exe`` path.

        Five independent oracles are applied, each catching a distinct failure mode:

        1. **Exact case-insensitive string equality** against the immutable literal
           ``c:\windows\system32\reg.exe``. Catches any drift to a different tool
           (e.g. ``regedit.exe``), a different root (e.g. SysWOW64), or a bare
           name.
        2. **PureWindowsPath component isolation** — drive == ``C:``, the path
           must include ``system32`` as a directory component (not ``syswow64``),
           and the name must be exactly ``reg.exe``.
        3. **SysWOW64 exclusion**: the constant must NOT start with
           ``c:\windows\syswow64\``. Both System32 and SysWOW64 paths pass the
           agent allowlist, so the allowlist oracle alone cannot distinguish them;
           this gate does.
        4. **Bare-name exclusion**: the constant must contain at least one path
           separator so it cannot be a bare name like ``"reg.exe"`` (the pre-fix
           value).
        5. **Allowlist acceptance**: the constant must satisfy
           :func:`is_windows_allowlisted`. This is the end-to-end gate that
           confirms the path the test pins is one the in-guest agent will accept.

        If the constant reverts to the pre-fix bare ``"reg.exe"`` value, oracles
        1-4 all fail independently of the allowlist, so no single oracle can be
        satisfied by a wrong value while the others silently pass.
        """
        canonical_lower: Final[str] = "c:\\windows\\system32\\reg.exe"

        lowered = WINDOWS_REG_EXE_PATH.lower()
        assert lowered == canonical_lower, (
            f"WINDOWS_REG_EXE_PATH {WINDOWS_REG_EXE_PATH!r} must equal the canonical "
            f"'C:\\Windows\\System32\\reg.exe' (case-insensitive); got {WINDOWS_REG_EXE_PATH!r} (F-0022)"
        )

        pw = PureWindowsPath(WINDOWS_REG_EXE_PATH)
        assert pw.drive.lower() == "c:", f"WINDOWS_REG_EXE_PATH drive must be 'C:', got {pw.drive!r} (F-0022)"
        path_parts_lower = [p.lower() for p in pw.parts]
        assert "system32" in path_parts_lower, (
            f"WINDOWS_REG_EXE_PATH {WINDOWS_REG_EXE_PATH!r} must contain 'System32' as a directory component "
            f"(parts: {list(pw.parts)!r}); 'SysWOW64' is not the right location for reg.exe (F-0022)"
        )
        assert pw.name.lower() == "reg.exe", (
            f"WINDOWS_REG_EXE_PATH {WINDOWS_REG_EXE_PATH!r} basename must be exactly 'reg.exe', got {pw.name!r} (F-0022)"
        )

        assert not lowered.startswith("c:\\windows\\syswow64\\"), (
            f"WINDOWS_REG_EXE_PATH {WINDOWS_REG_EXE_PATH!r} must use System32 root, not SysWOW64 "
            f"(both pass the allowlist; only System32 is correct for reg.exe) (F-0022)"
        )

        assert "\\" in WINDOWS_REG_EXE_PATH or "/" in WINDOWS_REG_EXE_PATH, (
            f"WINDOWS_REG_EXE_PATH {WINDOWS_REG_EXE_PATH!r} must be an absolute path, not a bare name "
            f"(pre-fix value was bare 'reg.exe' which the allowlist rejects) (F-0022)"
        )

        assert is_windows_allowlisted(WINDOWS_REG_EXE_PATH), (
            f"WINDOWS_REG_EXE_PATH {WINDOWS_REG_EXE_PATH!r} must satisfy the in-guest Test-AllowedCommand allowlist (F-0022)"
        )

    def test_allowlist_oracle_boundary_decisions(self) -> None:
        r"""Guard the host-side ``Test-AllowedCommand`` emulation at its boundaries.

        Pins the decisions the end-to-end dispatch tests rely on so the oracle
        itself is a trustworthy gate. Each assertion mirrors one branch of the
        in-guest PowerShell helper: empty rejected, bare names rejected unless
        explicitly allowlisted, ``.exe`` accepted only under the System32 /
        SysWOW64 / ``Z:\`` roots, and non-``.exe`` files under a valid root
        rejected. If any branch flips, the emulation would stop detecting an
        F-0022 regression in :meth:`apply_anti_evasion`.
        """
        assert is_windows_allowlisted("") is False, "empty command must be rejected"
        assert is_windows_allowlisted("reg.exe") is False, "bare 'reg.exe' must be rejected (F-0022 pre-fix value)"
        assert is_windows_allowlisted("powershell.exe") is True, "allowlisted bare name 'powershell.exe' must be accepted"
        assert is_windows_allowlisted("cmd") is True, "allowlisted bare name 'cmd' must be accepted"
        assert is_windows_allowlisted(r"C:\Windows\System32\reg.exe") is True, "absolute System32 reg.exe must be accepted"
        assert is_windows_allowlisted(r"C:\Windows\SysWOW64\reg.exe") is True, "absolute SysWOW64 reg.exe must be accepted"
        assert is_windows_allowlisted(r"Z:\monitor\agent.exe") is True, "absolute Z:\\ .exe must be accepted"
        assert is_windows_allowlisted(r"C:\Windows\System32\config.sys") is False, "non-.exe under System32 must be rejected"
        assert is_windows_allowlisted(r"C:\Temp\reg.exe") is False, "reg.exe outside an allowed root must be rejected"
        assert is_windows_allowlisted(WINDOWS_REG_EXE_PATH) is True, (
            f"the production WINDOWS_REG_EXE_PATH constant {WINDOWS_REG_EXE_PATH!r} must be allowlist-safe"
        )

    def test_apply_anti_evasion_dispatches_only_allowlisted_commands(self) -> None:
        """Every dispatched executable must pass the allowlist emulation.

        Drives the real ``apply_anti_evasion`` against a connected recording
        agent and asserts at least four ``reg.exe`` dispatches occurred, none
        used the bare ``reg.exe`` name, and every dispatched command satisfies
        the in-guest ``Test-AllowedCommand`` rule.
        """
        agent = _RecordingAgent()
        sb = _make_sandbox(anti_evasion_profile="default", agent=agent)

        asyncio.run(sb.apply_anti_evasion(profile="default"))

        assert len(agent.sent_commands) >= 5, (
            f"expected at least 4 reg.exe dispatches plus the MAC powershell call, got {agent.sent_commands!r}"
        )
        reg_dispatches = [(cmd, args) for cmd, args in agent.sent_commands if args and args[0] == "add"]
        assert len(reg_dispatches) == 4, f"expected exactly 4 reg.exe add dispatches, got {reg_dispatches!r}"
        for command, _args in agent.sent_commands:
            assert command != "reg.exe", "apply_anti_evasion dispatched bare 'reg.exe' (F-0022 regression)"
            assert is_windows_allowlisted(command), f"command {command!r} would be rejected by the in-guest allowlist"
        for command, _args in reg_dispatches:
            assert command == WINDOWS_REG_EXE_PATH, (
                f"reg.exe dispatch used {command!r}; F-0022 requires the absolute {WINDOWS_REG_EXE_PATH!r}"
            )

    @pytest.mark.parametrize("profile", ["default", "workstation", "laptop"])
    def test_apply_anti_evasion_records_full_technique_set(self, profile: ProfileName) -> None:
        """The result dict carries the exact ordered technique list for every profile.

        The expected technique list is an independent oracle frozen from the audit
        specification:

        * exactly three ``smbios_type_N_launch_arg`` entries (one per SMBIOS type),
        * exactly one ``cpuid_hypervisor_mask_launch_arg``,
        * exactly four ``registry_patch`` entries (manufacturer, product, product-id,
          disk model),
        * exactly one ``mac_address_randomize``.

        These counts are not derived from any production helper; they reflect the
        fixed F-0022 and F-0029 requirements. Multiple independent checks prevent
        a consistent-but-wrong implementation from passing:

        1. **Exact ordered list equality** against the immutable literal list
           ``_EXPECTED_FULL_TECHNIQUES``. If the implementation emits the wrong
           number of entries or wrong names, this gate fires.
        2. **Accepted-dispatch count equality**: every ``registry_patch`` entry must
           correspond to exactly one successful (``exit_code=0``) allowlist-safe
           dispatch. Pre-fix, all reg.exe dispatches returned ``-1``; this gate
           detects that silent failure.
        3. **SMBIOS prefix exclusivity**: each technique that begins with
           ``smbios_type_`` must end with ``_launch_arg`` and have a numeric type
           suffix (1, 2, or 3). A malformed or duplicated technique name fails this
           independent structural gate.
        4. **Non-SMBIOS technique names are literals**: ``cpuid_hypervisor_mask_launch_arg``
           and ``mac_address_randomize`` must appear at their exact positions in the
           list. Moving them or renaming them fails the exact-list gate.
        5. **Cross-profile identity differentiation**: the reg.exe dispatches for
           ``workstation`` and ``laptop`` must NOT write ``"HP"`` as the manufacturer
           (the pre-fix hardcoded value). The ``default`` profile must NOT write
           ``"Dell Inc."`` or ``"Lenovo"``. This gate catches a regression where the
           technique-set looks correct but the dispatched values are wrong.

        Args:
            profile: Anti-evasion profile to drive through ``apply_anti_evasion``.
        """
        expected_full_techniques: Final[list[str]] = [
            "smbios_type_1_launch_arg",
            "smbios_type_2_launch_arg",
            "smbios_type_3_launch_arg",
            "cpuid_hypervisor_mask_launch_arg",
            "registry_patch",
            "registry_patch",
            "registry_patch",
            "registry_patch",
            "mac_address_randomize",
        ]

        agent = _RecordingAgent()
        sb = _make_sandbox(anti_evasion_profile=profile, agent=agent)

        result: dict[str, Any] = asyncio.run(sb.apply_anti_evasion(profile=profile))

        assert set(result) == {"profile", "techniques", "count"}, f"unexpected result keys: {sorted(result)!r}"
        assert result["profile"] == profile

        raw_techniques: object = result["techniques"]
        assert isinstance(raw_techniques, list)
        techniques: list[str] = []
        for raw in cast("list[object]", raw_techniques):
            assert isinstance(raw, str)
            techniques.append(raw)

        assert result["count"] == len(techniques), (
            f"profile={profile!r}: count {result['count']!r} disagrees with techniques length {len(techniques)}"
        )

        assert techniques == expected_full_techniques, (
            f"profile={profile!r}: technique list does not match audit spec.\n"
            f"  expected: {expected_full_techniques!r}\n"
            f"  actual:   {techniques!r}"
        )

        accepted_reg_dispatches = sum(bool(args and args[0] == "add" and is_windows_allowlisted(cmd)) for cmd, args in agent.sent_commands)
        assert techniques.count("registry_patch") == accepted_reg_dispatches, (
            f"profile={profile!r}: each registry_patch technique must correspond to an accepted reg.exe dispatch: "
            f"techniques={techniques!r} accepted_reg_dispatches={accepted_reg_dispatches}"
        )

        smbios_techniques = [t for t in techniques if t.startswith("smbios_type_")]
        assert len(smbios_techniques) == 3, (
            f"profile={profile!r}: expected exactly 3 smbios_type_N_launch_arg techniques, got {smbios_techniques!r}"
        )
        for smbios_tech in smbios_techniques:
            assert smbios_tech.endswith("_launch_arg"), (
                f"profile={profile!r}: malformed SMBIOS technique name {smbios_tech!r}; must end with '_launch_arg'"
            )
            type_number = smbios_tech.removeprefix("smbios_type_").removesuffix("_launch_arg")
            assert type_number.isdigit(), (
                f"profile={profile!r}: SMBIOS technique {smbios_tech!r} has non-numeric type suffix {type_number!r}"
            )

        manufacturer_writes = [args for _cmd, args in agent.sent_commands if "SystemManufacturer" in args]
        assert len(manufacturer_writes) == 1, (
            f"profile={profile!r}: expected exactly 1 SystemManufacturer registry write, got {manufacturer_writes!r}"
        )
        actual_manufacturer = _reg_value_for(manufacturer_writes[0])

        if profile == "workstation":
            assert actual_manufacturer != "HP", (
                f"profile='workstation': SystemManufacturer must not be 'HP' (F-0029 pre-fix regression): got {actual_manufacturer!r}"
            )
        elif profile == "laptop":
            assert actual_manufacturer != "HP", (
                f"profile='laptop': SystemManufacturer must not be 'HP' (F-0029 pre-fix regression): got {actual_manufacturer!r}"
            )
            assert actual_manufacturer != "Dell Inc.", (
                f"profile='laptop': SystemManufacturer must not be 'Dell Inc.' (wrong profile identity): got {actual_manufacturer!r}"
            )
        else:
            assert actual_manufacturer != "Dell Inc.", (
                f"profile='default': SystemManufacturer must not be 'Dell Inc.': got {actual_manufacturer!r}"
            )
            assert actual_manufacturer != "Lenovo", (
                f"profile='default': SystemManufacturer must not be 'Lenovo': got {actual_manufacturer!r}"
            )

    def test_registry_patch_omitted_when_agent_rejects_commands(self) -> None:
        """A rejecting agent yields zero ``registry_patch`` techniques.

        Confirms the count is not hardcoded: an agent whose allowlist rejects
        every command (the pre-fix world) returns ``-1`` for each dispatch, so
        no ``registry_patch`` technique may be recorded while launch-time
        techniques remain. This proves the success test above is falsifiable.
        """

        class _RejectingAgent(_RecordingAgent):
            """Recording agent that rejects every dispatched command."""

            async def send_command(
                self,
                command: str,
                args: Sequence[str] | None = None,
                time_limit: float = 30.0,
            ) -> tuple[int, str, str]:
                """Record the dispatch and reject it unconditionally.

                Args:
                    command: Command name or path dispatched.
                    args: Argument list (recorded verbatim).
                    time_limit: Ignored.

                Returns:
                    tuple[int, str, str]: ``(-1, "", error)`` for every call.
                """
                del time_limit
                self.sent_commands.append((command, list(args) if args else []))
                return (-1, "", "rejected")

        agent = _RejectingAgent()
        sb = _make_sandbox(anti_evasion_profile="default", agent=agent)

        result: dict[str, Any] = asyncio.run(sb.apply_anti_evasion(profile="default"))

        raw_techniques: object = result["techniques"]
        assert isinstance(raw_techniques, list)
        techniques = [cast("str", t) for t in cast("list[object]", raw_techniques)]
        assert "registry_patch" not in techniques, f"rejected dispatches must record no registry_patch: {techniques!r}"
        assert "mac_address_randomize" not in techniques, f"rejected MAC dispatch must record no technique: {techniques!r}"
        assert techniques == _EXPECTED_LAUNCH_TECHNIQUES, f"only launch-time techniques should survive rejection: {techniques!r}"


class TestF0029IdentityProfileConsistency:
    """F-0029: SMBIOS and registry identity strings must agree per profile."""

    @pytest.mark.parametrize(
        ("profile", "required_manufacturer", "required_product"),
        [
            ("default", "HP", "HP EliteDesk 800 G6"),
            ("workstation", "Dell Inc.", "OptiPlex 7090"),
            ("laptop", "Lenovo", "ThinkPad T14 Gen 3"),
        ],
    )
    def test_launch_smbios_type1_matches_required_identity(
        self,
        profile: ProfileName,
        required_manufacturer: str,
        required_product: str,
        tmp_path: Path,
    ) -> None:
        """The real launch ``-smbios`` type-1 entry carries the required identity.

        The primary oracle is the ``(required_manufacturer, required_product)``
        pair embedded as literal strings in the parametrize decorator. To guard
        against the parametrize values themselves being wrong (e.g. copied from the
        implementation), three additional independent negative constraints are
        applied that do NOT reference the parametrize values at all:

        * For ``workstation``: the SMBIOS manufacturer must not be ``"HP"`` and the
          product must not be ``"HP EliteDesk 800 G6"`` (the pre-fix hardcoded
          values). Pre-fix, both would match the hardcoded ``"HP"`` default.
        * For ``laptop``: the manufacturer must be neither ``"HP"`` nor ``"Dell
          Inc."``; the product must be neither ``"HP EliteDesk 800 G6"`` nor
          ``"OptiPlex 7090"``.
        * For ``default``: the manufacturer must be neither ``"Dell Inc."`` nor
          ``"Lenovo"``; both are the non-default profile values.

        These negative constraints are hardcoded literals with no production
        dependency. An implementation that hardcodes ``"HP"`` for every profile
        fails the ``workstation`` and ``laptop`` parametrize cases AND the negative
        constraints, independently. An implementation that returns the right
        literals for the ``default`` profile but wrong literals for the other
        profiles fails the negative constraints for those profiles.

        Args:
            profile: Anti-evasion profile name.
            required_manufacturer: Exact manufacturer string the audit specifies.
            required_product: Exact product string the audit specifies.
            tmp_path: Per-test temporary directory for the disk/binary fixtures.
        """
        image = _make_disk_image(tmp_path)
        sb = _make_sandbox(anti_evasion_profile=profile, agent=None, image_path=image)
        sb.set_qemu_path(_make_qemu_binary(tmp_path))

        cmd = sb.build_command_for_test()
        manufacturer, product = _smbios_type1_identity_from_launch_cmd(cmd)

        assert manufacturer == required_manufacturer, (
            f"profile={profile!r}: launch -smbios manufacturer {manufacturer!r} != audit-required {required_manufacturer!r} (F-0029)"
        )
        assert product == required_product, (
            f"profile={profile!r}: launch -smbios product {product!r} != audit-required {required_product!r} (F-0029)"
        )

        if profile == "workstation":
            assert manufacturer != "HP", "profile='workstation': SMBIOS manufacturer must not be 'HP' (F-0029 pre-fix hardcoded regression)"
            assert product != "HP EliteDesk 800 G6", (
                "profile='workstation': SMBIOS product must not be 'HP EliteDesk 800 G6' (F-0029 pre-fix hardcoded regression)"
            )
        elif profile == "laptop":
            assert manufacturer != "HP", "profile='laptop': SMBIOS manufacturer must not be 'HP' (F-0029 pre-fix hardcoded regression)"
            assert manufacturer != "Dell Inc.", "profile='laptop': SMBIOS manufacturer must not be 'Dell Inc.' (wrong profile identity)"
            assert product != "HP EliteDesk 800 G6", (
                "profile='laptop': SMBIOS product must not be 'HP EliteDesk 800 G6' (F-0029 pre-fix hardcoded regression)"
            )
            assert product != "OptiPlex 7090", "profile='laptop': SMBIOS product must not be 'OptiPlex 7090' (wrong profile identity)"
        else:
            assert manufacturer != "Dell Inc.", (
                "profile='default': SMBIOS manufacturer must not be 'Dell Inc.' (workstation identity leaked)"
            )
            assert manufacturer != "Lenovo", "profile='default': SMBIOS manufacturer must not be 'Lenovo' (laptop identity leaked)"

    @pytest.mark.parametrize(
        ("profile", "required_manufacturer", "required_product"),
        [
            ("default", "HP", "HP EliteDesk 800 G6"),
            ("workstation", "Dell Inc.", "OptiPlex 7090"),
            ("laptop", "Lenovo", "ThinkPad T14 Gen 3"),
        ],
    )
    def test_registry_writes_use_required_identity(
        self,
        profile: ProfileName,
        required_manufacturer: str,
        required_product: str,
    ) -> None:
        """Registry ``SystemManufacturer`` / ``SystemProductName`` match the audit spec.

        The primary oracle is the ``(required_manufacturer, required_product)``
        pair embedded as literal strings in the parametrize decorator. To guard
        against the parametrize values drifting to match whatever the
        implementation happens to return (which is the same source for both SMBIOS
        and registry since they share :meth:`QEMUSandbox._anti_evasion_identity`),
        four additional independent negative constraints are applied:

        * For ``workstation`` and ``laptop``: the dispatched ``SystemManufacturer``
          value must NOT be ``"HP"`` and ``SystemProductName`` must NOT be
          ``"HP EliteDesk 800 G6"``. Pre-fix, both were hardcoded to ``"HP"`` /
          ``"HP EliteDesk 800 G6"`` for every profile; this gate catches that
          regression regardless of the parametrize oracle.
        * Cross-profile uniqueness: the ``SystemManufacturer`` value dispatched for
          ``workstation`` must not equal the one for ``laptop`` (both are non-HP).
          This is asserted by checking the actual written manufacturer against the
          other profile's known literal manufacturer.

        Args:
            profile: Anti-evasion profile to launch the sandbox with.
            required_manufacturer: Exact manufacturer string the audit specifies.
            required_product: Exact product string the audit specifies.
        """
        agent = _RecordingAgent()
        sb = _make_sandbox(anti_evasion_profile=profile, agent=agent)

        asyncio.run(sb.apply_anti_evasion(profile=profile))

        manufacturer_args = [args for _cmd, args in agent.sent_commands if "SystemManufacturer" in args]
        product_args = [args for _cmd, args in agent.sent_commands if "SystemProductName" in args]
        assert len(manufacturer_args) == 1, f"expected one SystemManufacturer write, got {manufacturer_args!r}"
        assert len(product_args) == 1, f"expected one SystemProductName write, got {product_args!r}"

        manufacturer_value = _reg_value_for(manufacturer_args[0])
        product_value = _reg_value_for(product_args[0])

        assert manufacturer_value == required_manufacturer, (
            f"profile={profile!r}: registry SystemManufacturer {manufacturer_value!r} != audit-required {required_manufacturer!r} (F-0029)"
        )
        assert product_value == required_product, (
            f"profile={profile!r}: registry SystemProductName {product_value!r} != audit-required {required_product!r} (F-0029)"
        )

        if profile == "workstation":
            assert manufacturer_value != "HP", (
                "profile='workstation': registry SystemManufacturer must not be 'HP' "
                "(F-0029 pre-fix hardcoded regression: all profiles wrote 'HP')"
            )
            assert product_value != "HP EliteDesk 800 G6", (
                "profile='workstation': registry SystemProductName must not be 'HP EliteDesk 800 G6' (F-0029 pre-fix hardcoded regression)"
            )
            assert manufacturer_value != "Lenovo", (
                "profile='workstation': registry SystemManufacturer must not be 'Lenovo' (that is the laptop identity, not workstation)"
            )
        elif profile == "laptop":
            assert manufacturer_value != "HP", (
                "profile='laptop': registry SystemManufacturer must not be 'HP' "
                "(F-0029 pre-fix hardcoded regression: all profiles wrote 'HP')"
            )
            assert product_value != "HP EliteDesk 800 G6", (
                "profile='laptop': registry SystemProductName must not be 'HP EliteDesk 800 G6' (F-0029 pre-fix hardcoded regression)"
            )
            assert manufacturer_value != "Dell Inc.", (
                "profile='laptop': registry SystemManufacturer must not be 'Dell Inc.' (that is the workstation identity, not laptop)"
            )
        else:
            assert manufacturer_value != "Dell Inc.", (
                "profile='default': registry SystemManufacturer must not be 'Dell Inc.' "
                "(workstation identity must not leak into default profile)"
            )
            assert manufacturer_value != "Lenovo", (
                "profile='default': registry SystemManufacturer must not be 'Lenovo' (laptop identity must not leak into default profile)"
            )

    @pytest.mark.parametrize(
        ("profile", "required_manufacturer", "required_product"),
        [
            ("default", "HP", "HP EliteDesk 800 G6"),
            ("workstation", "Dell Inc.", "OptiPlex 7090"),
            ("laptop", "Lenovo", "ThinkPad T14 Gen 3"),
        ],
    )
    def test_launch_smbios_and_registry_agree_with_each_other(
        self,
        profile: ProfileName,
        required_manufacturer: str,
        required_product: str,
        tmp_path: Path,
    ) -> None:
        """SMBIOS launch identity and registry identity agree with the frozen audit spec.

        Threads one profile through both production consumers and asserts all
        three of (launch SMBIOS, registry write, frozen audit spec) coincide.

        The key weakness of "compare two outputs from the same class" tests is
        that if both consumers share a bug they can still agree with each other
        while being wrong. This test counters that with two independent negative
        constraints that do not reference the parametrize oracle:

        1. **Pre-fix regression check**: for ``workstation`` and ``laptop``,
           both SMBIOS and registry manufacturer must NOT equal ``"HP"`` (the
           pre-fix hardcoded value). The pre-fix world has SMBIOS reporting the
           correct profile vendor but the registry hardcoded ``"HP"``; this
           constraint detects the mismatch without relying on the parametrize
           oracle being correct.
        2. **Cross-profile exclusion**: each profile's SMBIOS manufacturer
           must not equal the manufacturer assigned to ANY other profile.
           Concretely, ``workstation`` SMBIOS manufacturer != ``"Lenovo"``,
           ``laptop`` SMBIOS manufacturer != ``"Dell Inc."``, etc. These
           constraints come from the independently-frozen
           :data:`_EXPECTED_IDENTITY` dict, which is maintained separately
           from the production identity helper and encodes the audit contract
           for all three profiles.

        Args:
            profile: Anti-evasion profile to drive through both paths.
            required_manufacturer: Exact manufacturer string the audit specifies.
            required_product: Exact product string the audit specifies.
            tmp_path: Per-test temporary directory for the disk/binary fixtures.
        """
        image = _make_disk_image(tmp_path)
        smbios_sb = _make_sandbox(anti_evasion_profile=profile, agent=None, image_path=image)
        smbios_sb.set_qemu_path(_make_qemu_binary(tmp_path))
        smbios_manufacturer, smbios_product = _smbios_type1_identity_from_launch_cmd(smbios_sb.build_command_for_test())

        agent = _RecordingAgent()
        reg_sb = _make_sandbox(anti_evasion_profile=profile, agent=agent)
        asyncio.run(reg_sb.apply_anti_evasion(profile=profile))
        registry_manufacturer = _reg_value_for(next(args for _cmd, args in agent.sent_commands if "SystemManufacturer" in args))
        registry_product = _reg_value_for(next(args for _cmd, args in agent.sent_commands if "SystemProductName" in args))

        assert smbios_manufacturer == required_manufacturer, (
            f"profile={profile!r}: SMBIOS manufacturer {smbios_manufacturer!r} != frozen audit spec {required_manufacturer!r} (F-0029)"
        )
        assert registry_manufacturer == required_manufacturer, (
            f"profile={profile!r}: registry manufacturer {registry_manufacturer!r} != frozen audit spec {required_manufacturer!r} (F-0029)"
        )
        assert smbios_manufacturer == registry_manufacturer, (
            f"profile={profile!r}: SMBIOS/registry manufacturer mismatch: smbios={smbios_manufacturer!r} registry={registry_manufacturer!r}"
        )
        assert smbios_product == required_product, (
            f"profile={profile!r}: SMBIOS product {smbios_product!r} != frozen audit spec {required_product!r} (F-0029)"
        )
        assert registry_product == required_product, (
            f"profile={profile!r}: registry product {registry_product!r} != frozen audit spec {required_product!r} (F-0029)"
        )
        assert smbios_product == registry_product, (
            f"profile={profile!r}: SMBIOS/registry product mismatch: smbios={smbios_product!r} registry={registry_product!r}"
        )

        other_manufacturers = {_EXPECTED_IDENTITY[p][0] for p in _ALL_PROFILES if p != profile}
        if profile == "workstation":
            assert smbios_manufacturer != "HP", (
                "profile='workstation': SMBIOS manufacturer must not be 'HP' (F-0029 pre-fix hardcoded regression)"
            )
            assert registry_manufacturer != "HP", (
                "profile='workstation': registry manufacturer must not be 'HP' "
                "(F-0029 pre-fix hardcoded regression: registry was hardcoded regardless of profile)"
            )
            assert smbios_manufacturer not in other_manufacturers, (
                f"profile='workstation': SMBIOS manufacturer {smbios_manufacturer!r} "
                f"must not match another profile's manufacturer (cross-profile exclusion): {other_manufacturers!r}"
            )
        elif profile == "laptop":
            assert smbios_manufacturer != "HP", (
                "profile='laptop': SMBIOS manufacturer must not be 'HP' (F-0029 pre-fix hardcoded regression)"
            )
            assert registry_manufacturer != "HP", (
                "profile='laptop': registry manufacturer must not be 'HP' "
                "(F-0029 pre-fix hardcoded regression: registry was hardcoded regardless of profile)"
            )
            assert smbios_manufacturer not in other_manufacturers, (
                f"profile='laptop': SMBIOS manufacturer {smbios_manufacturer!r} "
                f"must not match another profile's manufacturer (cross-profile exclusion): {other_manufacturers!r}"
            )
        else:
            assert smbios_manufacturer not in other_manufacturers, (
                f"profile='default': SMBIOS manufacturer {smbios_manufacturer!r} "
                f"must not match another profile's manufacturer (cross-profile exclusion): {other_manufacturers!r}"
            )


class TestApplyAntiEvasionErrorPaths:
    """``apply_anti_evasion`` surfaces misconfiguration as ``SandboxError``."""

    def test_profile_mismatch_raises_sandbox_error(self) -> None:
        """Requesting a profile other than the launch profile raises.

        The result's launch-time techniques are fixed at ``start`` time, so a
        mismatched ``profile`` argument must surface as :class:`SandboxError`
        rather than silently returning techniques for the wrong profile.
        """
        agent = _RecordingAgent()
        sb = _make_sandbox(anti_evasion_profile="workstation", agent=agent)

        with pytest.raises(SandboxError, match="workstation"):
            asyncio.run(sb.apply_anti_evasion(profile="laptop"))
        assert agent.sent_commands == [], "no agent commands may be dispatched on profile mismatch"

    def test_not_running_raises_sandbox_error(self) -> None:
        """A non-running sandbox raises before dispatching any command."""
        agent = _RecordingAgent()
        sb = _make_sandbox(anti_evasion_profile="default", agent=agent)
        sb.state.status = "stopped"

        with pytest.raises(SandboxError):
            asyncio.run(sb.apply_anti_evasion(profile="default"))
        assert agent.sent_commands == [], "no agent commands may be dispatched when the sandbox is not running"

    def test_disconnected_qmp_raises_sandbox_error(self) -> None:
        """A disconnected QMP client raises before dispatching any command."""
        agent = _RecordingAgent()
        sb = _make_sandbox(anti_evasion_profile="default", agent=agent)
        sb.clear_qmp()

        with pytest.raises(SandboxError, match="QMP"):
            asyncio.run(sb.apply_anti_evasion(profile="default"))
        assert agent.sent_commands == [], "no agent commands may be dispatched when QMP is disconnected"
