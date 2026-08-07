# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Regression tests for S17-D41: the guest needs an absolute pointing device.

The VM Display encodes pointer input correctly. RFB ``PointerEvent`` carries
*absolute* framebuffer coordinates (RFC 6143 7.5.5) and ``vnc_widget.py`` packs
them exactly as specified. What was missing sat a layer below: the launcher
attached virtio NIC, virtio-serial and virtio-9p devices and no pointing device
at all, so every guest fell back to the q35 board's PS/2 mouse. Measured on a
live guest over its human monitor::

    (qemu) info mice
    * Mouse #2: QEMU PS/2 Mouse
    (qemu) info usb
    Error: USB support not enabled

A PS/2 mouse is a *relative* device. Handed absolute coordinates, QEMU has to
synthesize deltas from a cursor position it can only guess at, while the guest
applies its own pointer acceleration and clamps at the screen edges. The two
cursors diverge on the first movement and never resync, so a click is delivered
wherever the guest's cursor drifted to rather than where the operator aimed it.
From the operator's seat that is indistinguishable from a display that ignores
input, which is how it was first reported (S17-D39 symptom 2).

**Why this is not an assertion on the argument.** Naming ``usb-tablet`` in the
argv proves only that a string is present; whether the guest ends up with an
absolute pointer is a property of the emulated machine, and QEMU is the only
witness. :class:`TestTheGuestGetsAnAbsolutePointingDevice` therefore starts a
guest from the real :meth:`QEMUSandbox._build_qemu_command` argv and asks the
monitor what mice it has, then starts the identical machine with the tablet
removed and requires the absolute device to be gone.

Note the reading is *presence*, not the ``*`` marker. QEMU marks the current
mouse with ``*`` and only switches to the tablet once a guest driver enumerates
it, so a machine that has not booted an operating system still shows ``*`` on
the PS/2 mouse while correctly offering the tablet.

The live pair needs no accelerator, no disk and no guest: ``info mice`` answers
from the emulated machine itself. They still cannot run in the test container,
which has no QEMU, so they are registered in :mod:`tests._helpers.host_native`.
:class:`TestBothLaunchersOfferAnAbsolutePointer` runs anywhere and pins the two
argv builders to each other.
"""

from __future__ import annotations

import subprocess
import time
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.qemu import AcceleratorType
from scripts.sandbox.provision_windows_guest import InstallCommandSpec, build_install_command
from tests.sandbox.qemu.windows_boot_probe import (
    empty_qcow2,
    free_tcp_port,
    launcher_argv_for,
    make_scratch_disk,
    monitor_query,
    resolve_whpx_qemu_path,
    whpx_launcher_argv,
    with_monitor,
)


if TYPE_CHECKING:
    from pathlib import Path


_ABSOLUTE_MARKER: Final[str] = "(absolute)"
"""How ``info mice`` reports a device that accepts absolute coordinates."""

_TABLET_DEVICE_PREFIX: Final[str] = "usb-tablet"
"""Device model that provides the absolute pointer."""

_USB_CONTROLLER_PREFIX: Final[str] = "qemu-xhci"
"""Controller model the tablet attaches to; q35 supplies no USB bus itself."""

_DEVICE_OPTION: Final[str] = "-device"

_MACHINE_SETTLE_SECONDS: Final[float] = 6.0
"""Time allowed for QEMU to build the machine and open its monitor.

``info mice`` is answered by the emulated machine, not by a guest, so this only
has to cover process start and device construction.
"""

_SHUTDOWN_GRACE_SECONDS: Final[float] = 15.0


def _without_tablet(argv: list[str]) -> list[str]:
    """Rebuild an argv with the absolute pointing device removed.

    This reconstructs the machine as it stood before S17-D41: every other device
    identical, only the tablet gone. An argv this rewrite cannot change fails the
    calling test, which covers the one way the launcher can regress - dropping
    the tablet - so the discriminator can never quietly compare broken to broken.

    Args:
        argv: Launcher argv to rewrite.

    Returns:
        list[str]: The same vector without the tablet device.
    """
    stripped: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        is_tablet = token == _DEVICE_OPTION and index + 1 < len(argv) and argv[index + 1].startswith(_TABLET_DEVICE_PREFIX)
        if is_tablet:
            index += 2
            continue
        stripped.append(token)
        index += 1

    assert stripped != argv, (
        f"the launcher argv names no {_TABLET_DEVICE_PREFIX} device, so the guest has no absolute "
        f"pointer to take away and the S17-D41 discriminator cannot be built: {argv}"
    )
    return stripped


def _device_values(argv: list[str]) -> list[str]:
    """Collect every ``-device`` value in an argv.

    Args:
        argv: Argument vector to scan.

    Returns:
        list[str]: The value following each ``-device`` option, in order.
    """
    return [argv[index + 1] for index, token in enumerate(argv) if token == _DEVICE_OPTION and index + 1 < len(argv)]


def _mice(qemu_path: Path, argv: list[str]) -> str:
    """Start a machine, ask it what mice it has, and stop it again.

    Args:
        qemu_path: QEMU executable to run.
        argv: Argument vector, executable first.

    Returns:
        str: The monitor's ``info mice`` output.
    """
    monitor_port = free_tcp_port()
    full = with_monitor([str(qemu_path), *argv[1:]], monitor_port)
    process = subprocess.Popen(full, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(_MACHINE_SETTLE_SECONDS)
        return monitor_query(monitor_port, "info mice")
    finally:
        process.terminate()
        try:
            process.wait(timeout=_SHUTDOWN_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()


@pytest.fixture
def qemu_executable() -> Path:
    """Resolve the QEMU executable the launcher would use.

    Returns:
        Path: The resolved executable.
    """
    qemu_path, reason = resolve_whpx_qemu_path()
    if qemu_path is None:
        pytest.skip(reason)
    return qemu_path


class TestTheGuestGetsAnAbsolutePointingDevice:
    """The launcher's machine must offer a pointer that takes real coordinates."""

    def test_the_launcher_machine_offers_an_absolute_pointer(
        self,
        qemu_executable: Path,
        tmp_path: Path,
    ) -> None:
        """The real launch command builds a machine with an absolute pointer.

        Args:
            qemu_executable: Resolved QEMU executable.
            tmp_path: Per-test temporary directory for the disk.
        """
        disk = make_scratch_disk(qemu_executable, tmp_path / "s17d41-system.qcow2")
        argv = whpx_launcher_argv(disk)

        answer = _mice(qemu_executable, argv)

        assert _ABSOLUTE_MARKER in answer, (
            f"the launcher built a machine whose only pointing devices are relative, so VM Display "
            f"clicks cannot land where they were aimed (S17-D41). info mice said:\n{answer}\n"
            f"devices were: {_device_values(argv)}"
        )

    def test_removing_the_tablet_leaves_only_a_relative_mouse(
        self,
        qemu_executable: Path,
        tmp_path: Path,
    ) -> None:
        """The identical machine without the tablet has no absolute pointer.

        This is the live discriminator behind the companion test: it re-proves on
        every run that the absolute device comes from the tablet the launcher
        adds, rather than from something q35 would have supplied anyway.

        Args:
            qemu_executable: Resolved QEMU executable.
            tmp_path: Per-test temporary directory for the disk.
        """
        disk = make_scratch_disk(qemu_executable, tmp_path / "s17d41-relative.qcow2")
        argv = _without_tablet(whpx_launcher_argv(disk))

        answer = _mice(qemu_executable, argv)

        assert answer.strip(), (
            f"the monitor returned nothing for a machine built without the tablet, so it was never "
            f"observed and the absence of an absolute pointer is not evidence of anything: {argv}"
        )
        assert _ABSOLUTE_MARKER not in answer, (
            f"a machine built without {_TABLET_DEVICE_PREFIX} still reports an absolute pointer, so this "
            f"host supplies one by some other route and the companion S17-D41 gate proves nothing. "
            f"info mice said:\n{answer}"
        )


class TestBothLaunchersOfferAnAbsolutePointer:
    """The install command must build the same pointing hardware as the launcher."""

    @pytest.mark.parametrize("accelerator", list(AcceleratorType))
    def test_the_launcher_attaches_a_tablet_to_a_controller_it_also_adds(
        self,
        accelerator: AcceleratorType,
        tmp_path: Path,
    ) -> None:
        """A tablet needs a USB bus, and q35 provides none by itself.

        Args:
            accelerator: Accelerator the launcher is pinned to.
            tmp_path: Per-test temporary directory for the disk.
        """
        argv = launcher_argv_for(
            accelerator,
            empty_qcow2(tmp_path / "s17d41-mirror.qcow2"),
            tmp_path / "qemu-system-x86_64.exe",
        )
        devices = _device_values(argv)

        tablets = [device for device in devices if device.startswith(_TABLET_DEVICE_PREFIX)]
        controllers = [device for device in devices if device.startswith(_USB_CONTROLLER_PREFIX)]

        assert tablets, f"the {accelerator.value} launcher attaches no absolute pointer: {devices}"
        assert controllers, f"the {accelerator.value} launcher attaches no USB controller: {devices}"

        bus = next(part.split("=", 1)[1] for part in tablets[0].split(",") if part.startswith("bus="))
        controller_ids = {part.split("=", 1)[1] for device in controllers for part in device.split(",") if part.startswith("id=")}
        assert bus.rsplit(".", 1)[0] in controller_ids, (
            f"the tablet is attached to bus {bus!r}, which none of the controllers {controllers} provides, "
            f"so QEMU will refuse to build the machine (S17-D41)"
        )

    def test_the_install_command_builds_the_same_pointing_hardware(self, tmp_path: Path) -> None:
        """The provisioner mirrors the launcher, so the install is drivable too.

        Args:
            tmp_path: Per-test temporary directory for the referenced media.
        """
        spec = InstallCommandSpec(
            qemu_executable=tmp_path / "qemu-system-x86_64.exe",
            accelerator=AcceleratorType.WHPX.value,
            cpu_cores=4,
            memory_mb=8192,
            disk_image=tmp_path / "guest.qcow2",
            install_iso=tmp_path / "windows.iso",
            answer_iso=tmp_path / "answer.iso",
            virtio_iso=tmp_path / "virtio.iso",
            display="none",
            vnc_port=5900,
            agent_port=4445,
        )
        install_devices = _device_values(build_install_command(spec))
        launcher_devices = _device_values(
            launcher_argv_for(
                AcceleratorType.WHPX,
                empty_qcow2(tmp_path / "guest.qcow2"),
                tmp_path / "qemu-system-x86_64.exe",
            ),
        )

        for prefix in (_TABLET_DEVICE_PREFIX, _USB_CONTROLLER_PREFIX):
            assert any(device.startswith(prefix) for device in launcher_devices), (
                f"the launcher no longer adds {prefix}, so there is nothing for the installer to mirror"
            )
            assert any(device.startswith(prefix) for device in install_devices), (
                f"the install command omits {prefix} that the launcher adds, so the guest being installed "
                f"cannot be driven with a pointer even though the guest it becomes can (S17-D41): "
                f"{install_devices}"
            )
