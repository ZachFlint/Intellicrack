# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D58: a sandbox must never write the configured disk image.

``_build_qemu_command`` attached the configured qcow2 read-write, with no
per-instance overlay and no ``snapshot=on``, so every instance built from one
``QEMUConfig`` received a byte-identical ``-drive`` line pointing at the same
file. QEMU takes no image lock on Windows, so nothing refused the second open:
two guests simply wrote over each other.

Measured on 2026-08-07: instances ``7306f4ec`` and ``0b0b8e09`` ran
concurrently against ``windows11-intellicrack-v4.qcow2``; ``qemu-img check``
afterwards reported *41 errors were found on the image. Data may be corrupted,
or further writes to the image may corrupt it.* The untouched sibling copy
reported *No errors were found on the image*, so the image was sound going in.
The damage is silent - both guests appeared to run normally.

This became reachable only once S17-D56 allowed two instances to exist, and the
GUI's Compare control needs two runs, so the documented workflow led into it.

The gate drives the real launch composition - provision the launch disk, then
assemble the argv around it - on two sandboxes sharing one image, and checks
the disk each guest would actually open. It needs a real ``qemu-img`` to build
and verify overlays, which the test container does not carry, so it runs in the
host-native pass.
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox


# Big enough to be a real qcow2 with a real header, small enough that creating
# two of them costs nothing.
_BASE_IMAGE_SIZE: Final[str] = "64M"
_QEMU_IMG_TIMEOUT_S: Final[float] = 60.0
_SUCCESS: Final[int] = 0
_EXPECTED_INSTANCES: Final[int] = 2
_BACKING_FILE_FIELD: Final[str] = "backing file:"
_DIGEST_CHUNK: Final[int] = 1 << 20


def _digest(path: Path) -> str:
    """Hash a file so an unchanged image can be proven unchanged.

    Args:
        path: File to hash.

    Returns:
        str: Hex SHA-256 digest.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_DIGEST_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _qemu_img() -> Path:
    """Locate the qemu-img that ships beside the bundled QEMU.

    Returns:
        Path: Path to qemu-img.

    Raises:
        RuntimeError: If qemu-img cannot be found on this host.
    """
    bundled = QEMUSandbox.TOOLS_PATH / "qemu-img.exe"
    if bundled.exists():
        return bundled
    found = shutil.which("qemu-img")
    if found is not None:
        return Path(found)
    message = "qemu-img is required by this gate and was not found"
    raise RuntimeError(message)


def _run_qemu_img(*args: str) -> subprocess.CompletedProcess[str]:
    """Run qemu-img and capture its output.

    Args:
        *args: Arguments after the executable.

    Returns:
        subprocess.CompletedProcess[str]: The finished process.
    """
    return subprocess.run(
        [str(_qemu_img()), *args],
        capture_output=True,
        text=True,
        timeout=_QEMU_IMG_TIMEOUT_S,
        check=False,
    )


@pytest.fixture
def base_image(tmp_path: Path) -> Path:
    """Create a real qcow2 to stand in for a provisioned guest image.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: The freshly created, uncorrupted base image.
    """
    image = tmp_path / "base-guest.qcow2"
    result = _run_qemu_img("create", "-f", "qcow2", str(image), _BASE_IMAGE_SIZE)
    assert result.returncode == _SUCCESS, f"could not create the base image: {result.stderr}"
    return image


class _OverlaySandbox(QEMUSandbox):
    """``QEMUSandbox`` subclass exposing the command builder to test code.

    The wrapped method is the real production implementation.
    """

    async def prepare(self) -> None:
        """Create the instance temp dir and resolve the QEMU binary."""
        assert await self.is_available(), "QEMU is required by this gate and was not found"
        await self._prepare_qemu_shared_folders()

    async def build_command(self) -> list[str]:
        """Drive the real launch path that decides which disk QEMU opens.

        This is the same composition :meth:`QEMUSandbox._spawn_qemu_process`
        performs - provision the launch disk, then assemble the argv around it
        - so the gate judges what a real launch would attach rather than what
        the argument builder does on its own.

        Returns:
            list[str]: The assembled QEMU argument vector.
        """
        return await self._build_qemu_command(await self._launch_disk_path())

    async def clean_up(self) -> None:
        """Release this sandbox's temporary state and host ports."""
        await self._cleanup()


def _disk_argument(argv: list[str]) -> str:
    """Extract the path of the disk the guest boots from.

    Args:
        argv: A built QEMU command line.

    Returns:
        str: The ``file=`` value of the qcow2 ``-drive``.

    Raises:
        AssertionError: If no qcow2 drive is present.
    """
    for index, token in enumerate(argv):
        if token == "-drive" and "format=qcow2" in argv[index + 1]:
            return argv[index + 1].split(",", 1)[0].removeprefix("file=")
    message = f"no qcow2 -drive was present on the command line: {argv}"
    raise AssertionError(message)


async def _build_two(base: Path) -> tuple[list[str], list[str], _OverlaySandbox, _OverlaySandbox]:
    """Build command lines for two sandboxes sharing one configured image.

    Args:
        base: The shared backing image.

    Returns:
        tuple[list[str], list[str], _OverlaySandbox, _OverlaySandbox]: Both
        argument vectors and both sandboxes, the latter for teardown.
    """
    sandboxes: list[_OverlaySandbox] = []
    argvs: list[list[str]] = []
    for _ in range(_EXPECTED_INSTANCES):
        config = QEMUConfig(guest_os=GuestOS.WINDOWS, image_path=base)
        sandbox = _OverlaySandbox(config=SandboxConfig(), qemu_config=config)
        await sandbox.prepare()
        sandboxes.append(sandbox)
        argvs.append(await sandbox.build_command())
    return argvs[0], argvs[1], sandboxes[0], sandboxes[1]


class TestTwoSandboxesNeverOpenTheSameWritableDisk:
    """One configured image must not become two guests' writable disk."""

    @pytest.mark.asyncio
    async def test_each_sandbox_gets_its_own_disk(self, base_image: Path) -> None:
        """Two sandboxes on one image must boot from two different files.

        Args:
            base_image: The shared backing image.
        """
        first, second, sandbox_a, sandbox_b = await _build_two(base_image)
        try:
            disk_a = _disk_argument(first)
            disk_b = _disk_argument(second)

            assert disk_a != disk_b, f"both sandboxes were given the same writable disk: {disk_a}"
            assert Path(disk_a) != base_image, "the first sandbox writes directly to the configured image"
            assert Path(disk_b) != base_image, "the second sandbox writes directly to the configured image"
        finally:
            await sandbox_a.clean_up()
            await sandbox_b.clean_up()

    @pytest.mark.asyncio
    async def test_each_disk_is_backed_by_the_configured_image(self, base_image: Path) -> None:
        """The overlays must actually present the configured image's contents.

        A private disk that is not backed by the guest image would isolate the
        sandboxes and boot nothing, which is not a fix.

        Args:
            base_image: The shared backing image.
        """
        first, second, sandbox_a, sandbox_b = await _build_two(base_image)
        try:
            for argv in (first, second):
                disk = _disk_argument(argv)
                info = _run_qemu_img("info", disk)
                assert info.returncode == _SUCCESS, f"qemu-img info failed: {info.stderr}"

                # The backing-file line is the discriminator: a disk that IS the
                # configured image names itself under "image:" but has no
                # backing file at all.
                backing = [line for line in info.stdout.splitlines() if line.startswith(_BACKING_FILE_FIELD)]
                assert backing, f"the sandbox disk has no backing file, so it is not an overlay:\n{info.stdout}"
                assert str(base_image) in backing[0], (
                    f"the sandbox disk is backed by something other than the configured image: {backing[0]}"
                )
        finally:
            await sandbox_a.clean_up()
            await sandbox_b.clean_up()

    @pytest.mark.asyncio
    async def test_writing_through_both_disks_never_touches_the_image(self, base_image: Path) -> None:
        """Writing via both sandboxes' disks must leave the image byte-identical.

        This is the defect's actual consequence. The check is "unchanged"
        rather than "still passes ``qemu-img check``" deliberately: writing
        through the shared image is a legal qcow2 operation that leaves it
        structurally valid, so a validity check alone cannot tell the two
        arrangements apart. Only a guest can corrupt it, but any write reaching
        the configured image at all is the defect.

        Args:
            base_image: The shared backing image.
        """
        first, second, sandbox_a, sandbox_b = await _build_two(base_image)
        try:
            before = await asyncio.to_thread(_digest, base_image)

            # Resizing rewrites qcow2 metadata, so it is a real structural write
            # through each sandbox's own disk rather than a no-op.
            for argv in (first, second):
                resize = await asyncio.to_thread(_run_qemu_img, "resize", _disk_argument(argv), "+16M")
                assert resize.returncode == _SUCCESS, f"could not write through the sandbox disk: {resize.stderr}"

            after = await asyncio.to_thread(_digest, base_image)
            assert after == before, "a sandbox wrote to the configured disk image, which a second sandbox would corrupt"

            check = _run_qemu_img("check", str(base_image))
            assert check.returncode == _SUCCESS, f"the configured image no longer checks clean:\n{check.stdout}"
        finally:
            await sandbox_a.clean_up()
            await sandbox_b.clean_up()
