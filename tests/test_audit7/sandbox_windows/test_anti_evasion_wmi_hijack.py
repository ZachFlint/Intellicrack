# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Regression tests for audit7 F-0013: WMI provider hijack via MOF compilation.

The pre-fix ``WindowsSandbox.apply_anti_evasion`` wrote spoofed manufacturer /
product / BIOS values to ``HKLM:\HARDWARE\DESCRIPTION\System\BIOS`` and
sibling keys. That registry hive is **volatile**: it is rebuilt by the Windows
kernel at every boot from PnP enumeration, so any writes vanish before
sandboxed samples actually read them. Evasive malware in any case queries the
WMI providers (``Win32_ComputerSystem``, ``Win32_ComputerSystemProduct``,
``Win32_BIOS``), not the raw hive.

The fix:

1. Drops every ``HKLM:\HARDWARE\DESCRIPTION`` write.
2. Generates a MOF file from the active anti-evasion profile that redefines
   the three target classes as ``[Static]`` with the spoofed instance values.
3. Compiles the MOF inside the guest via ``mofcomp.exe -N:root\cimv2 <mof>``.
4. Verifies via ``Get-CimInstance`` that the spoofed values are now returned.

These tests assert each of those properties without launching a real Windows
Sandbox by overriding the dispatcher-backed ``run_command`` with a recording
fake.
"""

from __future__ import annotations

import asyncio
import json
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.windows import (
    WindowsSandbox,
    build_anti_evasion_mof,
    resolve_anti_evasion_profile,
)


if TYPE_CHECKING:
    from collections.abc import Callable


def _extract_mof_identity(mof_text: str) -> dict[str, str]:
    """Extract the spoofed identity values out of a generated MOF file.

    The MOF declares ``instance of Win32_ComputerSystem``,
    ``instance of Win32_ComputerSystemProduct``, and ``instance of Win32_BIOS``
    with concrete spoofed string values. This helper parses those lines so
    test handlers can reproduce the exact payload ``Get-CimInstance`` should
    return without relying on the non-deterministic
    :func:`resolve_anti_evasion_profile` generator.

    Args:
        mof_text: MOF source produced by :func:`build_anti_evasion_mof`.

    Returns:
        dict[str, str]: Mapping with keys ``Manufacturer``, ``Model``,
        ``ProductName``, ``ProductVendor``, ``BIOSVendor`` and ``BIOSVersion``.
    """

    def _grab(pattern: str) -> str:
        """Return the first capture group for ``pattern`` against ``mof_text``.

        Args:
            pattern: Regex with a single capture group.

        Returns:
            str: Captured value, or empty string when not found.
        """
        match = re.search(pattern, mof_text)
        return match.group(1) if match else ""

    return {
        "Manufacturer": _grab(r'\binstance of Win32_ComputerSystem\b[\s\S]*?Manufacturer\s*=\s*"([^"]+)";'),
        "Model": _grab(r'\binstance of Win32_ComputerSystem\b[\s\S]*?Model\s*=\s*"([^"]+)";'),
        "ProductName": _grab(r'\binstance of Win32_ComputerSystemProduct\b[\s\S]*?Name\s*=\s*"([^"]+)";'),
        "ProductVendor": _grab(r'\binstance of Win32_ComputerSystemProduct\b[\s\S]*?Vendor\s*=\s*"([^"]+)";'),
        "BIOSVendor": _grab(r'\binstance of Win32_BIOS\b[\s\S]*?Manufacturer\s*=\s*"([^"]+)";'),
        "BIOSVersion": _grab(r'\binstance of Win32_BIOS\b[\s\S]*?SMBIOSBIOSVersion\s*=\s*"([^"]+)";'),
    }


class _RecordingSandbox(WindowsSandbox):
    """WindowsSandbox subclass that records dispatched commands.

    Replaces :meth:`WindowsSandbox.run_command` with a programmable fake so
    tests can drive ``apply_anti_evasion`` without launching a real sandbox
    process. The fake records every command in :attr:`commands` and returns
    the value produced by the installed handler.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialise the recording sandbox.

        Args:
            config: Optional sandbox configuration.
        """
        super().__init__(config)
        self.commands: list[str] = []
        self._handler: Callable[[str], tuple[int, str, str]] | None = None

    def install_shared_folder(self, path: Path) -> None:
        """Pre-populate the shared folder pointer for tests.

        Args:
            path: Directory that should be treated as the shared folder root.
        """
        self._shared_folder = path

    def get_shared_folder(self) -> Path | None:
        """Return the shared folder pointer.

        Returns:
            Path | None: Configured shared folder, or ``None`` if unset.
        """
        return self._shared_folder

    def set_handler(self, handler: Callable[[str], tuple[int, str, str]]) -> None:
        """Install the dispatch handler that produces canned responses.

        Args:
            handler: Callable mapping a command string to
                ``(exit_code, stdout, stderr)``.
        """
        self._handler = handler

    async def run_command(
        self,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Record ``command`` and return the handler's response.

        Args:
            command: Command sent to the sandbox dispatcher.
            time_limit: Ignored.
            working_directory: Ignored.

        Returns:
            tuple[int, str, str]: Handler-supplied ``(exit_code, stdout, stderr)``.
        """
        del time_limit, working_directory
        self.commands.append(command)
        if self._handler is None:
            return (0, "", "")
        return self._handler(command)


def _make_recording_sandbox(tmp_path: Path) -> _RecordingSandbox:
    """Build a recording sandbox set to ``running`` with a shared folder.

    Args:
        tmp_path: Pytest temporary directory to use as the shared folder.

    Returns:
        _RecordingSandbox: Ready-to-use sandbox with status ``running``.
    """
    sb = _RecordingSandbox(config=SandboxConfig())
    shared = tmp_path / "shared"
    shared.mkdir(parents=True, exist_ok=True)
    (shared / "input").mkdir(parents=True, exist_ok=True)
    sb.install_shared_folder(shared)
    sb.state.status = "running"
    return sb


class TestF0013AntiEvasionMOFGeneration:
    """F-0013: anti-evasion must generate a profile-driven MOF file."""

    def test_default_profile_mof_contains_hp_manufacturer(self) -> None:
        """The default profile MOF declares HP as manufacturer."""
        profile = resolve_anti_evasion_profile("default")
        assert profile.manufacturer == "HP"
        mof = build_anti_evasion_mof(profile, machine_name="DESKTOP-AAAAAA")
        assert 'Manufacturer = "HP"' in mof
        assert "Win32_ComputerSystem" in mof
        assert "Win32_ComputerSystemProduct" in mof
        assert "Win32_BIOS" in mof
        assert "#pragma deleteclass" in mof
        assert "[Static" in mof

    def test_workstation_profile_mof_contains_dell(self) -> None:
        """The workstation profile MOF declares Dell manufacturer / OptiPlex model."""
        profile = resolve_anti_evasion_profile("workstation")
        mof = build_anti_evasion_mof(profile, machine_name="DESKTOP-BBBBBB")
        assert 'Manufacturer = "Dell Inc."' in mof
        assert "OptiPlex 7090" in mof
        assert "DESKTOP-BBBBBB" in mof

    def test_laptop_profile_mof_contains_lenovo(self) -> None:
        """The laptop profile MOF declares Lenovo manufacturer / ThinkPad model."""
        profile = resolve_anti_evasion_profile("laptop")
        mof = build_anti_evasion_mof(profile, machine_name="DESKTOP-CCCCCC")
        assert 'Manufacturer = "Lenovo"' in mof
        assert "ThinkPad T14 Gen 3" in mof

    def test_unknown_profile_falls_back_to_default(self) -> None:
        """Unknown profile names route to the default profile."""
        profile = resolve_anti_evasion_profile("xyzzy")
        assert profile.name == "default"
        assert profile.manufacturer == "HP"


class TestF0013AntiEvasionNoVolatileRegistryWrites:
    """F-0013: apply_anti_evasion must not write to the volatile HARDWARE hive."""

    def test_no_hklm_hardware_writes(self, tmp_path: Path) -> None:
        r"""apply_anti_evasion never dispatches ``HKLM:\HARDWARE`` registry writes.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)

        def handler(cmd: str) -> tuple[int, str, str]:
            """Respond to the verification query with values pulled from the staged MOF.

            Args:
                cmd: Command sent to the sandbox.

            Returns:
                tuple[int, str, str]: Canned (exit_code, stdout, stderr).
            """
            if "Get-CimInstance" in cmd:
                shared = sb.get_shared_folder()
                assert shared is not None
                mof_files = list((shared / "input").glob("intellicrack_antievasion_*.mof"))
                assert mof_files, "expected a staged MOF before verification query is issued"
                payload = _extract_mof_identity(mof_files[0].read_text(encoding="utf-8"))
                return (0, json.dumps(payload), "")
            return (0, "", "")

        sb.set_handler(handler)

        result = asyncio.run(sb.apply_anti_evasion(profile="default"))

        for cmd in sb.commands:
            lowered = cmd.lower()
            assert "hklm:\\hardware\\description" not in lowered, f"volatile HARDWARE write leaked: {cmd!r}"
            assert "hklm:\\hardware\\" not in lowered, f"unexpected HARDWARE hive write: {cmd!r}"

        assert any("mofcomp" in cmd.lower() for cmd in sb.commands), "expected mofcomp invocation"
        assert "wmi_hijack_win32_computersystem" in result["techniques"]


class TestF0013AntiEvasionMOFCompilationAndVerification:
    """F-0013: ``apply_anti_evasion`` must compile a MOF and verify spoofed values."""

    def test_mofcomp_invoked_with_staged_mof_file(self, tmp_path: Path) -> None:
        """The MOF file is staged on disk and ``mofcomp.exe`` is dispatched against it.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)

        def handler(cmd: str) -> tuple[int, str, str]:
            """Reply to the verification query with values pulled from the staged MOF.

            Args:
                cmd: Command sent to the sandbox dispatcher.

            Returns:
                tuple[int, str, str]: ``(0, stdout, "")``.
            """
            if "Get-CimInstance" in cmd:
                shared = sb.get_shared_folder()
                assert shared is not None
                mof_files = list((shared / "input").glob("intellicrack_antievasion_*.mof"))
                assert mof_files, "expected a staged MOF before verification query is issued"
                payload = _extract_mof_identity(mof_files[0].read_text(encoding="utf-8"))
                return (0, json.dumps(payload), "")
            return (0, "", "")

        sb.set_handler(handler)

        shared = sb.get_shared_folder()
        assert shared is not None
        input_dir = shared / "input"
        existing_mofs = set(input_dir.glob("intellicrack_antievasion_*.mof"))

        asyncio.run(sb.apply_anti_evasion(profile="default"))

        staged_mofs = set(input_dir.glob("intellicrack_antievasion_*.mof")) - existing_mofs
        assert len(staged_mofs) == 1, f"expected exactly one staged MOF; found {staged_mofs!r}"
        staged_path = next(iter(staged_mofs))
        mof_text = staged_path.read_text(encoding="utf-8")
        assert "Win32_ComputerSystem" in mof_text
        assert "[Static" in mof_text
        assert "Manufacturer" in mof_text

        mofcomp_cmds = [c for c in sb.commands if "mofcomp" in c.lower()]
        assert mofcomp_cmds, "mofcomp.exe was never dispatched"
        assert staged_path.name in mofcomp_cmds[0]
        assert "root\\cimv2" in mofcomp_cmds[0]

    def test_verification_failure_raises_sandbox_error(self, tmp_path: Path) -> None:
        """When ``Get-CimInstance`` returns wrong values, ``apply_anti_evasion`` must raise.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)

        def handler(cmd: str) -> tuple[int, str, str]:
            """Respond to verification with unspoofed values to trigger mismatch.

            Args:
                cmd: Command being dispatched.

            Returns:
                tuple[int, str, str]: Canned response.
            """
            if "Get-CimInstance" in cmd:
                payload = json.dumps({
                    "Manufacturer": "QEMU",
                    "Model": "Standard PC (Q35 + ICH9)",
                    "ProductName": "QEMU Virtual Machine",
                    "ProductVendor": "QEMU",
                    "BIOSVendor": "SeaBIOS",
                    "BIOSVersion": "1.0",
                })
                return (0, payload, "")
            return (0, "", "")

        sb.set_handler(handler)

        with pytest.raises(SandboxError) as exc:
            asyncio.run(sb.apply_anti_evasion(profile="default"))
        assert "WMI hijack verification" in str(exc.value)

    def test_mofcomp_nonzero_exit_raises_sandbox_error(self, tmp_path: Path) -> None:
        """When ``mofcomp.exe`` fails, ``apply_anti_evasion`` must raise.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)

        def handler(cmd: str) -> tuple[int, str, str]:
            """Fail every mofcomp invocation.

            Args:
                cmd: Command being dispatched.

            Returns:
                tuple[int, str, str]: ``(1, "", "compile failed")`` for mofcomp.
            """
            if "mofcomp" in cmd.lower():
                return (1, "", "compile failed")
            return (0, "", "")

        sb.set_handler(handler)

        with pytest.raises(SandboxError) as exc:
            asyncio.run(sb.apply_anti_evasion(profile="default"))
        assert "compile" in str(exc.value).lower() or "mofcomp" in str(exc.value).lower()


class TestF0013AntiEvasionSuccessfulFlow:
    """F-0013: end-to-end success path returns the WMI hijack technique markers."""

    def test_successful_flow_reports_wmi_hijack_techniques(self, tmp_path: Path) -> None:
        """A spoofed-payload run reports the three WMI hijack techniques and observed values.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)

        def handler(cmd: str) -> tuple[int, str, str]:
            """Reply to ``Get-CimInstance`` with values pulled from the staged MOF.

            Args:
                cmd: Command being dispatched.

            Returns:
                tuple[int, str, str]: Canned response.
            """
            if "Get-CimInstance" in cmd:
                shared = sb.get_shared_folder()
                assert shared is not None
                mof_files = list((shared / "input").glob("intellicrack_antievasion_*.mof"))
                assert mof_files, "expected a staged MOF before verification query is issued"
                payload = _extract_mof_identity(mof_files[0].read_text(encoding="utf-8"))
                return (0, json.dumps(payload), "")
            return (0, "", "")

        sb.set_handler(handler)

        result: dict[str, Any] = asyncio.run(sb.apply_anti_evasion(profile="workstation"))

        techniques = result["techniques"]
        assert isinstance(techniques, list)
        assert "wmi_hijack_win32_computersystem" in techniques
        assert "wmi_hijack_win32_computersystemproduct" in techniques
        assert "wmi_hijack_win32_bios" in techniques

        hijack = result["wmi_hijack"]
        assert isinstance(hijack, dict)
        assert hijack["status"] == "verified"
        assert hijack["observed_manufacturer"] == "Dell Inc."
        assert hijack["observed_model"] == "OptiPlex 7090"


class TestF0013AntiEvasionRejectsNonRunning:
    """F-0013: ``apply_anti_evasion`` must reject calls when the sandbox is not running."""

    def test_raises_when_state_not_running(self, tmp_path: Path) -> None:
        """A stopped sandbox refuses to apply anti-evasion and never dispatches.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        sb.state.status = "stopped"

        with pytest.raises(SandboxError):
            asyncio.run(sb.apply_anti_evasion(profile="default"))
        assert not sb.commands, "no commands should be dispatched against a stopped sandbox"


def test_mof_text_is_well_formed_for_each_profile() -> None:
    """Smoke check: every profile produces a non-empty MOF with the expected pragmas."""
    for profile_name in ("default", "workstation", "laptop"):
        profile = resolve_anti_evasion_profile(profile_name)
        mof = build_anti_evasion_mof(profile, machine_name=f"DESKTOP-{profile_name.upper()[:3]}123")
        assert mof.startswith("#pragma autorecover")
        assert "#pragma namespace" in mof
        assert mof.count("instance of") == 3
        assert mof.count("#pragma deleteclass") == 3
        with tempfile.NamedTemporaryFile(suffix=".mof", mode="w", delete=False, encoding="utf-8") as fh:
            fh.write(mof)
            staged = Path(fh.name)
        try:
            assert staged.read_text(encoding="utf-8") == mof
        finally:
            staged.unlink()
