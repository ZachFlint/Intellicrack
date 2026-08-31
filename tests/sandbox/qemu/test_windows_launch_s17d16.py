# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D16/D17/D18/D19: the QEMU backend must launch on Windows.

The QEMU backend had never run on Windows. Its command line and process model
carried Unix assumptions that make QEMU exit before the VM starts:

* ``-daemonize`` and ``-pidfile`` (S17-D16) - Windows QEMU implements neither;
  ``-daemonize`` is rejected as an invalid option, so every launch failed.
* virtio-9p for the Linux shared folder (S17-D17) - 9p is compiled out of every
  Windows QEMU build, so ``-fsdev`` aborts the launch.
* ``-cpu host`` and a q35 in-kernel IRQ chip under WHPX (companions of S17-D18) -
  both make WHPX raise "Unexpected VP exit code 4" during early boot.
* ``-smbios type=3,...,chassis-type=N`` (S17-D19) - ``chassis-type`` is not a
  valid SMBIOS type-3 parameter, so QEMU rejects the argument.

These tests build the real command line with ``_build_qemu_command`` and assert
the argv is one Windows QEMU actually accepts, and exercise the real foreground
process model that replaces the daemonized one.
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import AcceleratorType, GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows QEMU launch contract")


def _make_qcow2(tmp_path: Path) -> Path:
    """Write a minimal but real qcow2 v3 header the argv can point at.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Path: Path to the created qcow2 image file.
    """
    header = b"QFI\xfb" + (3).to_bytes(4, "big") + bytes(64)
    image = tmp_path / "guest.qcow2"
    image.write_bytes(header)
    return image


def _whpx_sandbox(tmp_path: Path, guest_os: GuestOS) -> QEMUSandbox:
    """Build a QEMU sandbox primed as if WHPX detection had already run.

    Args:
        tmp_path: Per-test temporary directory.
        guest_os: Guest OS the command line should target.

    Returns:
        QEMUSandbox: A sandbox with a WHPX accelerator, a resolved binary
        path, and a prepared shared folder, ready for ``_build_qemu_command``.
    """
    image = _make_qcow2(tmp_path)
    sandbox = QEMUSandbox(SandboxConfig(), QEMUConfig(guest_os=guest_os, image_path=image))
    shared = tmp_path / "shared"
    shared.mkdir()
    # Prime the state _start_impl would have established before building argv.
    for attr, value in (
        ("_accelerator", AcceleratorType.WHPX),
        ("_qemu_path", tmp_path / "qemu-system-x86_64.exe"),
        ("_temp_dir", tmp_path),
        ("_shared_folder", shared),
    ):
        setattr(sandbox, attr, value)
    return sandbox


def _build(sandbox: QEMUSandbox) -> list[str]:
    """Build the real QEMU command line for a sandbox.

    Args:
        sandbox: The sandbox whose command line to build.

    Returns:
        list[str]: The assembled QEMU argv.
    """
    builder = getattr(sandbox, "_build_qemu_command")
    return asyncio.run(builder())


def test_no_daemonize_or_pidfile_on_windows(tmp_path: Path) -> None:
    """Windows QEMU rejects ``-daemonize`` and never writes a ``-pidfile``.

    Args:
        tmp_path: Per-test temporary directory.
    """
    argv = _build(_whpx_sandbox(tmp_path, GuestOS.LINUX))
    assert "-daemonize" not in argv, "-daemonize is an invalid option on Windows QEMU"
    assert "-pidfile" not in argv, "Windows QEMU never produces a pidfile, so it must not be requested"


def test_whpx_pins_a_supported_irqchip_mode_and_a_compatible_cpu(tmp_path: Path) -> None:
    """The WHPX machine and CPU must be ones WHPX can actually run.

    WHPX supports exactly two interrupt-chip modes: ``on`` puts the local APIC
    in the hypervisor and ``off`` routes it through userspace. ``split`` is
    rejected outright ("WHPX: split irqchip currently not supported"), and
    leaving the mode unpinned lets the q35 default decide it. Which of the two
    supported modes actually carries a guest is settled against a live guest by
    the S17-D37 gate, not by restating the chosen spelling here.

    Args:
        tmp_path: Per-test temporary directory.
    """
    argv = _build(_whpx_sandbox(tmp_path, GuestOS.LINUX))
    machine = argv[argv.index("-machine") + 1]
    cpu = argv[argv.index("-cpu") + 1]
    assert "accel=whpx" in machine
    irqchip_modes = [token.split("=", 1)[1] for token in machine.split(",") if token.startswith("kernel-irqchip=")]
    assert irqchip_modes, f"WHPX must pin an interrupt-chip mode rather than inherit the q35 default; got {machine!r}"
    assert irqchip_modes[-1] in {"on", "off"}, f"WHPX only implements the on and off interrupt chips; got {irqchip_modes[-1]!r}"
    assert cpu.startswith("qemu64"), f"WHPX cannot virtualize -cpu host/max; got {cpu!r}"
    assert "hypervisor=off" in cpu, "the anti-evasion CPU masks must survive the WHPX-compatible model"


def test_linux_shared_folder_uses_fat_not_9p_on_windows(tmp_path: Path) -> None:
    """The Linux shared folder must not use virtio-9p, which Windows QEMU lacks.

    The FAT volume that replaces it is exposed read-only: vvfat's write-back
    path calls ``abort()`` rather than failing a write, which took the whole
    machine down mid-run (S17-D69).

    Args:
        tmp_path: Per-test temporary directory.
    """
    argv = _build(_whpx_sandbox(tmp_path, GuestOS.LINUX))
    joined = " ".join(argv)
    assert "-fsdev" not in argv, "virtio-9p (-fsdev) is compiled out of Windows QEMU"
    assert "virtio-9p-pci" not in joined
    assert "file=fat:" in joined, "the shared folder must be a FAT block device on Windows"
    assert "fat:rw:" not in joined, "a writable vvfat volume aborts QEMU from its commit path (S17-D69)"
    assert "readonly=on" in joined, "the FAT shared folder must be exposed read-only (S17-D69)"


def test_smbios_entries_carry_no_invalid_chassis_type(tmp_path: Path) -> None:
    """No ``-smbios`` argument may use the rejected ``chassis-type`` parameter.

    Args:
        tmp_path: Per-test temporary directory.
    """
    argv = _build(_whpx_sandbox(tmp_path, GuestOS.LINUX))
    smbios_values = [argv[i + 1] for i, tok in enumerate(argv) if tok == "-smbios"]
    assert smbios_values, "the anti-evasion profile must still emit SMBIOS entries"
    for value in smbios_values:
        assert "chassis-type" not in value, f"chassis-type is not a valid SMBIOS type-3 parameter: {value!r}"


def test_resolve_pid_reads_the_foreground_child_on_windows(tmp_path: Path) -> None:
    """With no pidfile, the PID comes from the live foreground QEMU child.

    Args:
        tmp_path: Per-test temporary directory.
    """

    async def _run() -> None:
        sandbox = _whpx_sandbox(tmp_path, GuestOS.LINUX)
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        sandbox.process = proc
        try:
            resolved = await getattr(sandbox, "_resolve_qemu_pid")()
            assert resolved == proc.pid, "Windows PID must come from the foreground child, not a pidfile"
        finally:
            await getattr(sandbox, "_reap_foreground_qemu")()
            assert sandbox.process is None, "reap must release the child handle"
            assert proc.returncode is not None, "reap must leave no running QEMU child behind"

    asyncio.run(_run())
