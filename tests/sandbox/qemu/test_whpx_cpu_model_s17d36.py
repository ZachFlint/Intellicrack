# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Regression tests for S17-D36: the WHPX ``-cpu`` model must start Windows.

``QEMUSandbox._build_qemu_command`` selects a CPU model per accelerator. Under
WHPX it cannot pass ``host`` or ``max`` - the guest triple-faults into
``WHPX: Unexpected VP exit code 4`` - so the model was plain ``qemu64``. Bare
``qemu64`` advertises neither SSE4.2 nor POPCNT, both of which Windows 11 24H2
requires, so a Windows guest triple-faulted with that identical WHPX exit code
before its boot manager produced a single line of output. The entire Windows
QEMU path was therefore unreachable on this platform, which is also what hid
S17-D35 (the guest agent binding loopback) behind it: no Windows guest had ever
reached the point of running an agent.

The fix names the two features explicitly - WHPX accepts them individually,
what it rejects is the whole host feature set.

These gates do not assert on the CPU string. A substring assertion would only
restate the production constant, and the property that matters is not the
spelling of the argument but whether a real Windows kernel accepts the
processor it describes. So:

* :class:`TestTheWhpxCpuModelStartsAWindowsKernel` takes the ``-cpu`` argument
  the real :meth:`QEMUSandbox._build_qemu_command` emits, starts real Windows
  installation media under WHPX with it, and requires the machine to still be
  running after the window the fault falls in. It then starts the *same*
  command with the named features stripped back out and requires that one to
  abort with the WHPX exit-code message. The second half is a live
  discriminator rather than a control constant: it re-proves on every run that
  this media really does reject a featureless ``qemu64``, so the first half
  cannot pass vacuously.

  What this gates is precisely the S17-D36 boundary - whether the Windows
  kernel accepts the processor it is handed, or the machine dies before it can
  execute anything. Whether the guest then goes on to reach Setup is a separate
  property of the machine model, gated by
  :mod:`tests.sandbox.qemu.test_whpx_irqchip_s17d37`.
* :class:`TestTheLauncherAndProvisionerAgreeOnTheWhpxCpuModel` gates the second
  copy of the rule. ``scripts.sandbox.provision_windows_guest`` builds the
  install-time command line and must select the same processor, or the disk the
  installer produces boots on a machine the sandbox cannot reproduce.

The boot class is host-native: the test container has no hypervisor. It is
registered in :mod:`tests._helpers.host_native`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.qemu import AcceleratorType
from scripts.sandbox.provision_windows_guest import runtime_cpu_argument, runtime_machine_argument
from tests.sandbox.qemu.windows_boot_probe import (
    WHPX_ABORT_MARKER,
    argument_value,
    empty_qcow2,
    images_directory,
    launcher_argv_for,
    make_scratch_disk,
    observe_boot,
    replace_argument_value,
    resolve_whpx_qemu_path,
    whpx_launcher_argv,
    windows_install_media,
    with_boot_media,
)


if TYPE_CHECKING:
    from pathlib import Path


_BOOT_SURVIVAL_SECONDS: Final[float] = 75.0
"""How long the good command must stay alive to count as having started.

The triple fault is raised by the guest's very first instructions - the failing
runs observed while diagnosing S17-D36 aborted within a few seconds, long
before the boot manager drew anything. Seventy-five seconds is far past that.
"""

_BOOT_ABORT_SECONDS: Final[float] = 75.0
"""How long the featureless command is given to abort before it counts as alive."""

_CPU_FLAG_PREFIX: Final[str] = "+"


def _without_named_features(cpu_argument: str) -> str:
    """Strip every explicitly named CPU feature from a ``-cpu`` value.

    This reconstructs the model as it stood before S17-D36: the same base model
    and the same anti-evasion masks, minus the ``+feature`` tokens.

    A value that names no feature fails the calling test: there is then nothing
    to strip, the discriminator cannot be built, and the launcher has regressed
    to exactly the model S17-D36 describes.

    Args:
        cpu_argument: The launcher's ``-cpu`` value.

    Returns:
        str: The value with all ``+feature`` tokens removed.
    """
    tokens = cpu_argument.split(",")
    kept = [token for token in tokens if not token.startswith(_CPU_FLAG_PREFIX)]
    assert len(kept) < len(tokens), (
        f"the launcher's -cpu value {cpu_argument!r} names no +feature, so the WHPX Windows-start discriminator cannot be built (S17-D36)"
    )
    return ",".join(kept)


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


class TestTheWhpxCpuModelStartsAWindowsKernel:
    """The launcher's WHPX processor must be one Windows agrees to run on."""

    def test_the_launcher_cpu_model_is_accepted_by_the_windows_install_media(
        self,
        whpx_host: Path,
        install_media: Path,
        tmp_path: Path,
    ) -> None:
        """The real launch command survives the window the triple fault falls in.

        Args:
            whpx_host: Resolved QEMU executable on a WHPX-capable host.
            install_media: Windows installation medium to start.
            tmp_path: Per-test temporary directory for the scratch disk.
        """
        disk = make_scratch_disk(whpx_host, tmp_path / "s17d36-system.qcow2")
        argv = with_boot_media(whpx_launcher_argv(disk), install_media)

        outcome = observe_boot(argv, _BOOT_SURVIVAL_SECONDS)

        assert not outcome.exited, (
            f"the launcher's WHPX command died within {_BOOT_SURVIVAL_SECONDS}s "
            f"(exit {outcome.returncode}) starting {install_media.name} with "
            f"-cpu {argument_value(argv, '-cpu')!r} (S17-D36):\n{outcome.output}"
        )

    def test_stripping_the_named_features_triple_faults_the_same_media(
        self,
        whpx_host: Path,
        install_media: Path,
        tmp_path: Path,
    ) -> None:
        """The identical command without the named features is rejected by WHPX.

        This is the live discriminator behind the companion test: it proves on
        every run that this medium genuinely refuses a featureless ``qemu64``,
        so surviving the start is a real result and not an artefact of a medium
        that would have run on anything.

        Args:
            whpx_host: Resolved QEMU executable on a WHPX-capable host.
            install_media: Windows installation medium to start.
            tmp_path: Per-test temporary directory for the scratch disk.
        """
        disk = make_scratch_disk(whpx_host, tmp_path / "s17d36-featureless.qcow2")
        launcher_argv = whpx_launcher_argv(disk)
        featureless = _without_named_features(argument_value(launcher_argv, "-cpu"))
        argv = with_boot_media(replace_argument_value(launcher_argv, "-cpu", featureless), install_media)

        outcome = observe_boot(argv, _BOOT_ABORT_SECONDS)

        assert outcome.aborted_on_whpx_exception, (
            f"starting {install_media.name} with -cpu {featureless!r} did not abort with "
            f"{WHPX_ABORT_MARKER!r} (exited={outcome.exited}, exit={outcome.returncode}), so this "
            f"medium no longer discriminates on the CPU features and the companion "
            f"S17-D36 gate proves nothing:\n{outcome.output}"
        )


class TestTheLauncherAndProvisionerAgreeOnTheWhpxCpuModel:
    """The install-time and run-time command lines must select one machine.

    ``scripts.sandbox.provision_windows_guest`` performs the unattended install
    on its own command line. If it selects a different processor or machine
    type from the one the sandbox later boots the resulting disk on, the guest
    is installed against hardware the launcher cannot reproduce - and under
    WHPX neither mismatch is cosmetic: one is the difference between booting
    and a triple fault, the other between booting and a hang.
    """

    @pytest.mark.parametrize("accelerator", list(AcceleratorType))
    def test_the_provisioner_cpu_argument_matches_the_launcher(
        self,
        accelerator: AcceleratorType,
        tmp_path: Path,
    ) -> None:
        """Both mirrors emit the same ``-cpu`` value for every accelerator.

        Args:
            accelerator: Accelerator under test.
            tmp_path: Per-test temporary directory for the image fixture.
        """
        argv = launcher_argv_for(accelerator, empty_qcow2(tmp_path / "disk.qcow2"), tmp_path / "qemu-system-x86_64.exe")

        assert argument_value(argv, "-cpu") == runtime_cpu_argument(accelerator.value), (
            f"accelerator={accelerator.value}: the provisioner installs against a different processor than the launcher boots on (S17-D36)"
        )

    @pytest.mark.parametrize("accelerator", list(AcceleratorType))
    def test_the_provisioner_machine_argument_matches_the_launcher(
        self,
        accelerator: AcceleratorType,
        tmp_path: Path,
    ) -> None:
        """Both mirrors emit the same ``-machine`` value for every accelerator.

        Args:
            accelerator: Accelerator under test.
            tmp_path: Per-test temporary directory for the image fixture.
        """
        argv = launcher_argv_for(accelerator, empty_qcow2(tmp_path / "disk.qcow2"), tmp_path / "qemu-system-x86_64.exe")

        assert argument_value(argv, "-machine") == runtime_machine_argument(accelerator.value), (
            f"accelerator={accelerator.value}: the provisioner installs on a different machine type than the launcher boots on (S17-D37)"
        )
