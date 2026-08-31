# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Regression tests for S17-D37: the WHPX interrupt chip must reach the guest.

With the S17-D36 CPU model in place a Windows 11 24H2 guest finally started -
and then hung forever. Measured over the QEMU human monitor, the guest was at
ring 0 with interrupts enabled (``RFL=0x202``), spinning in a backward-``jmp``
loop that polled a global, while QEMU's own ``info irq`` counted **45080**
IRQ 0 events on both the i8259 and the ioapic. QEMU was raising timer
interrupts the guest never received: its boot spinner did not advance one
frame in ninety seconds and its disk never grew past 0.38 MB in fifteen
minutes.

The cause was ``kernel-irqchip=off``, forced under WHPX. WHPX emulates the
local APIC *inside the hypervisor* - QEMU announces ``WHPX: setting APIC
emulation mode in the hypervisor`` when asked for it - and that is the only
mode that delivers interrupts to a Windows guest. Flipping that single token to
``on`` takes the same media from a permanent hang to Windows Setup in about a
minute. The comment that justified ``off`` blamed ``Unexpected VP exit code 4``
on the IRQ chip, which is the same symptom S17-D36 turned out to be, so the
option was disabled for a fault it never caused.

**Why this is not an assertion on the argument.** A test that asserted
``"kernel-irqchip=on" in machine`` would be the same shape as the assertion
this defect invalidated at ``test_windows_launch_s17d16.py`` - it pinned the
*wrong* value with total confidence and could never have caught this, because
nothing about the string tells you whether interrupts arrive. The only witness
is a guest. So :class:`TestTheWhpxInterruptChipReachesAWindowsGuest` starts the
real installation media with the argument the real
:meth:`QEMUSandbox._build_qemu_command` emits and requires the guest to draw a
user interface, then starts the identical command with that one token flipped
back and requires it to draw nothing but its boot logo.

Coverage of the framebuffer is the reading, and the two states are an order of
magnitude apart rather than marginally different: the boot logo is a small
glyph on black, Windows Setup is a full dialog. The second test is a live
discriminator, not a control constant - it re-proves on every run that this
medium really does hang without the in-hypervisor APIC.

Host-native: the test container has no hypervisor. Registered in
:mod:`tests._helpers.host_native`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from tests.sandbox.qemu.windows_boot_probe import (
    argument_value,
    free_tcp_port,
    images_directory,
    make_scratch_disk,
    observe_rendering,
    replace_argument_value,
    resolve_whpx_qemu_path,
    whpx_launcher_argv,
    windows_install_media,
    with_boot_media,
    with_monitor,
)


if TYPE_CHECKING:
    from pathlib import Path

    from tests.sandbox.qemu.windows_boot_probe import RenderObservation


_RENDER_WINDOW_SECONDS: Final[float] = 240.0
"""Longest a guest is watched for a rendered user interface.

Windows Setup appeared in about 66 seconds on the host this defect was
diagnosed on. The window is set well past that so a slower host still passes,
and it is also what the hung half has to survive without rendering.
"""

_SAMPLE_INTERVAL_SECONDS: Final[float] = 10.0
"""Delay between framebuffer samples."""

_UI_COVERAGE_THRESHOLD: Final[float] = 0.10
"""Non-black coverage that counts as a rendered user interface.

Measured on this medium: the Windows boot logo covers well under 1% of a
1024x768 framebuffer, the Setup dialog covers most of it. A tenth is an order
of magnitude above the hung state and an order of magnitude below the running
one, so nothing lands near the line.
"""

_IRQCHIP_OPTION: Final[str] = "kernel-irqchip"
_USERSPACE_IRQCHIP: Final[str] = f"{_IRQCHIP_OPTION}=off"
_MACHINE_OPTION: Final[str] = "-machine"


def _with_userspace_irqchip(machine_argument: str) -> str:
    """Rewrite a ``-machine`` value to route interrupts through userspace.

    This reconstructs the machine as it stood before S17-D37: every other
    token identical, only the interrupt chip changed back.

    A value this rewrite cannot change fails the calling test. That covers both
    ways the launcher can regress: naming no interrupt chip at all, and already
    naming the userspace one. Either way the discriminator cannot be built, and
    the launcher has stopped asking WHPX for the in-hypervisor APIC that this
    defect is about.

    Args:
        machine_argument: The launcher's ``-machine`` value.

    Returns:
        str: The same value with the interrupt chip set to ``off``.
    """
    tokens = machine_argument.split(",")
    rewritten = [_USERSPACE_IRQCHIP if token.startswith(f"{_IRQCHIP_OPTION}=") else token for token in tokens]
    assert rewritten != tokens, (
        f"the launcher's -machine value {machine_argument!r} is already what this rewrite produces, so it either "
        f"names no {_IRQCHIP_OPTION} or already routes interrupts through userspace, and the WHPX "
        f"interrupt-delivery discriminator cannot be built (S17-D37)"
    )
    return ",".join(rewritten)


def _watch(argv: list[str], frame_directory: Path) -> RenderObservation:
    """Start a guest with a monitor attached and watch what it renders.

    Args:
        argv: Launcher argv already carrying boot media.
        frame_directory: Directory the sampled frames are written to.

    Returns:
        RenderObservation: Peak coverage and when the threshold was crossed.
    """
    frame_directory.mkdir(parents=True, exist_ok=True)
    monitor_port = free_tcp_port()
    return observe_rendering(
        with_monitor(argv, monitor_port),
        monitor_port,
        frame_directory,
        window_seconds=_RENDER_WINDOW_SECONDS,
        coverage_threshold=_UI_COVERAGE_THRESHOLD,
        sample_interval_seconds=_SAMPLE_INTERVAL_SECONDS,
    )


@pytest.fixture
def whpx_host() -> Path:
    """Resolve the QEMU executable, requiring a WHPX-capable host.

    Returns:
        Path: The QEMU executable the launcher would use.
    """
    qemu_path, reason = resolve_whpx_qemu_path()
    if qemu_path is None:
        pytest.skip(reason)
    return qemu_path


@pytest.fixture
def install_media() -> Path:
    """Locate staged Windows installation media.

    Returns:
        Path: The install medium found in the bundled image directory.
    """
    media = windows_install_media()
    if media is None:
        pytest.skip(f"no Windows installation media staged in {images_directory()}")
    return media


class TestTheWhpxInterruptChipReachesAWindowsGuest:
    """The launcher's WHPX machine must deliver interrupts to a Windows guest."""

    def test_the_launcher_machine_lets_the_windows_installer_render_its_ui(
        self,
        whpx_host: Path,
        install_media: Path,
        tmp_path: Path,
    ) -> None:
        """The real launch command gets the installer as far as drawing a UI.

        Args:
            whpx_host: Resolved QEMU executable on a WHPX-capable host.
            install_media: Windows installation medium to start.
            tmp_path: Per-test temporary directory for the disk and frames.
        """
        disk = make_scratch_disk(whpx_host, tmp_path / "s17d37-system.qcow2")
        argv = with_boot_media(whpx_launcher_argv(disk), install_media)

        observed = _watch(argv, tmp_path / "frames-launcher")

        assert observed.crossed_after is not None, (
            f"the launcher's WHPX machine {argument_value(argv, _MACHINE_OPTION)!r} never got "
            f"{install_media.name} past its boot logo: peak coverage {observed.peak_coverage:.4f} over "
            f"{observed.frames} frames in {_RENDER_WINDOW_SECONDS}s never reached "
            f"{_UI_COVERAGE_THRESHOLD} (exited={observed.exited}, exit={observed.returncode}). "
            f"The guest is starting and then receiving no interrupts (S17-D37):\n{observed.output}"
        )

    def test_routing_interrupts_through_userspace_hangs_the_same_media(
        self,
        whpx_host: Path,
        install_media: Path,
        tmp_path: Path,
    ) -> None:
        """The identical command with the userspace IRQ chip renders nothing.

        This is the live discriminator behind the companion test: it proves on
        every run that this medium genuinely hangs without the in-hypervisor
        APIC, so rendering a UI is a real result and not something that would
        have happened under any interrupt configuration.

        Args:
            whpx_host: Resolved QEMU executable on a WHPX-capable host.
            install_media: Windows installation medium to start.
            tmp_path: Per-test temporary directory for the disk and frames.
        """
        disk = make_scratch_disk(whpx_host, tmp_path / "s17d37-userspace.qcow2")
        launcher_argv = whpx_launcher_argv(disk)
        userspace = _with_userspace_irqchip(argument_value(launcher_argv, _MACHINE_OPTION))
        argv = with_boot_media(replace_argument_value(launcher_argv, _MACHINE_OPTION, userspace), install_media)

        observed = _watch(argv, tmp_path / "frames-userspace")

        assert observed.crossed_after is None, (
            f"starting {install_media.name} with -machine {userspace!r} reached a rendered UI after "
            f"{observed.crossed_after}s (peak coverage {observed.peak_coverage:.4f}), so this medium no "
            f"longer discriminates on interrupt delivery and the companion S17-D37 gate proves "
            f"nothing:\n{observed.output}"
        )
        assert observed.frames > 0, (
            f"no framebuffer was captured at all in {_RENDER_WINDOW_SECONDS}s "
            f"(exited={observed.exited}, exit={observed.returncode}), so the guest was never observed "
            f"and its failure to render is not evidence of anything:\n{observed.output}"
        )
