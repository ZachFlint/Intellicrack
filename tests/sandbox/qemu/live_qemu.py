# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""A real, disposable QEMU process with an open QMP monitor, for host-native gates.

Gates that judge what QEMU actually answers need QEMU, not a description of it.
This module starts a genuine ``qemu-system-x86_64`` with a genuine qcow2
attached and a genuine QMP monitor listening, so the production monitor client
talks to the real protocol implementation.

The guest deliberately runs under TCG with no boot media. These gates exercise
the monitor, not the guest, and TCG keeps the Host Compute Service - which
Windows shares with Docker - entirely out of the picture.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from intellicrack.sandbox.qemu import QEMUSandbox


if TYPE_CHECKING:
    from collections.abc import Iterator


IMAGE_SIZE: Final[str] = "64M"
GUEST_MEMORY_MB: Final[str] = "128"
QEMU_IMG_TIMEOUT_S: Final[float] = 60.0
QEMU_READY_TIMEOUT_S: Final[float] = 30.0
QEMU_EXIT_TIMEOUT_S: Final[float] = 30.0
POLL_INTERVAL_S: Final[float] = 0.2
SUCCESS: Final[int] = 0

ACCEL_TCG: Final[str] = "tcg"
ACCEL_WHPX: Final[str] = "whpx"
# WHPX needs a real feature set to initialise and a Windows guest needs its APIC
# emulated in the hypervisor; these mirror the production launch in
# QEMUSandbox._build_qemu_command. WHPX registers the migration blockers that
# make a machine-state snapshot impossible at init, with no guest running, so a
# ``-S`` machine is enough to exercise the disk-only path.
_WHPX_MACHINE: Final[str] = "q35,accel=whpx,kernel-irqchip=on"
_WHPX_CPU: Final[str] = "qemu64,+sse4.2,+popcnt"


class QemuLaunchError(RuntimeError):
    """QEMU exited before its monitor came up - e.g. the accelerator is absent."""


def qemu_tool(name: str) -> Path:
    """Locate a QEMU executable, preferring the copy Intellicrack bundles.

    Args:
        name: Executable stem, such as ``qemu-img``.

    Returns:
        Path: Path to the executable.

    Raises:
        RuntimeError: If it cannot be found on this host.
    """
    bundled = QEMUSandbox.TOOLS_PATH / f"{name}.exe"
    if bundled.exists():
        return bundled
    found = shutil.which(name)
    if found is not None:
        return Path(found)
    message = f"{name} is required by this gate and was not found"
    raise RuntimeError(message)


def run_qemu_img(*args: str) -> subprocess.CompletedProcess[str]:
    """Run qemu-img and capture its output.

    Args:
        *args: Arguments after the executable.

    Returns:
        subprocess.CompletedProcess[str]: The finished process.
    """
    return subprocess.run(
        [str(qemu_tool("qemu-img")), *args],
        capture_output=True,
        text=True,
        timeout=QEMU_IMG_TIMEOUT_S,
        check=False,
    )


def tags_on_disk(image: Path) -> list[str]:
    """Read an image's snapshot tags with qemu-img, outside QEMU entirely.

    This is an independent oracle: it does not go through the QMP connection
    the production code uses, so it cannot agree with a broken implementation
    by sharing its mistake.

    Args:
        image: Image to inspect.

    Returns:
        list[str]: Snapshot tags stored in that image.

    Raises:
        RuntimeError: If qemu-img could not read the image.
    """
    result = run_qemu_img("info", "--output=json", str(image))
    if result.returncode != SUCCESS:
        message = f"qemu-img info failed: {result.stderr}"
        raise RuntimeError(message)
    info = cast("dict[str, Any]", json.loads(result.stdout))
    entries = info.get("snapshots")
    if not isinstance(entries, list):
        return []
    tags: list[str] = []
    for entry in cast("list[object]", entries):
        if isinstance(entry, dict):
            name = cast("dict[str, Any]", entry).get("name")
            if isinstance(name, str):
                tags.append(name)
    return tags


def bindable_port() -> int:
    """Pick a host port by binding for real.

    ``connect_ex`` cannot answer "can I bind" on Windows, where reserved
    ranges refuse a bind while nothing listens - the finding behind S17-D56.

    Returns:
        int: A port this host will let QEMU bind.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class LiveQemu:
    """A real QEMU process with a real qcow2 and an open QMP monitor."""

    def __init__(self, image: Path, monitor_port: int, process: subprocess.Popen[bytes]) -> None:
        """Record the running QEMU and what it holds open.

        Args:
            image: The qcow2 the machine has attached.
            monitor_port: Host port carrying the QMP monitor.
            process: The running QEMU process.
        """
        self.image = image
        self.monitor_port = monitor_port
        self._process = process

    def stop(self) -> None:
        """End the QEMU process and wait for it to release the image."""
        if self._process.poll() is None:
            self._process.kill()
        try:
            self._process.wait(timeout=QEMU_EXIT_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=QEMU_EXIT_TIMEOUT_S)


def wait_for_monitor(port: int, process: subprocess.Popen[bytes]) -> None:
    """Block until the QMP monitor accepts a connection.

    Args:
        port: Monitor port.
        process: The QEMU process, so an early exit is told from a slow start.

    Raises:
        QemuLaunchError: If QEMU exited before the monitor came up.
        RuntimeError: If the monitor never came up though QEMU is still alive.
    """
    deadline = time.monotonic() + QEMU_READY_TIMEOUT_S
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
            message = f"QEMU exited with code {process.returncode} before its monitor came up: {stderr.strip() or '(no output)'}"
            raise QemuLaunchError(message)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return
        except OSError:
            time.sleep(POLL_INTERVAL_S)
    message = f"the QEMU monitor on port {port} never accepted a connection"
    raise RuntimeError(message)


def _live_qemu_argv(image: Path, memory_mb: str, port: int, accel: str) -> list[str]:
    """Build the argv for a disposable live QEMU on one accelerator.

    Args:
        image: The qcow2 to attach.
        memory_mb: Guest RAM in megabytes.
        port: Host port for the QMP monitor.
        accel: Accelerator name, :data:`ACCEL_TCG` or :data:`ACCEL_WHPX`.

    Returns:
        list[str]: The full command line.
    """
    qemu = str(qemu_tool("qemu-system-x86_64"))
    drive = f"file={image},format=qcow2,if=virtio"
    monitor = f"tcp:127.0.0.1:{port},server=on,wait=off"
    if accel == ACCEL_WHPX:
        # ``-S`` leaves the machine paused: the migration blockers this gate
        # needs are registered by WHPX at init, not by anything a guest does.
        return [
            qemu,
            *["-machine", _WHPX_MACHINE],
            *["-cpu", _WHPX_CPU],
            *["-m", memory_mb],
            *["-display", "none"],
            "-nodefaults",
            "-S",
            *["-drive", drive],
            *["-qmp", monitor],
        ]
    return [
        qemu,
        *["-machine", "q35"],
        *["-accel", ACCEL_TCG],
        *["-m", memory_mb],
        *["-display", "none"],
        "-nodefaults",
        *["-drive", drive],
        *["-qmp", monitor],
    ]


def start_live_qemu(workdir: Path, memory_mb: str = GUEST_MEMORY_MB, accel: str = ACCEL_TCG) -> Iterator[LiveQemu]:
    """Start a real QEMU on a fresh qcow2 and yield it until the caller is done.

    :meth:`wait_for_monitor` raises :class:`QemuLaunchError` when QEMU exits
    before its monitor comes up, which on the WHPX path means the accelerator is
    not usable on this host; that propagates to the caller.

    Args:
        workdir: Directory the image is created in.
        memory_mb: Guest RAM in megabytes. Gates that measure work proportional
            to guest memory - a full memory dump, for one - need more than the
            minimum this module defaults to.
        accel: Accelerator to launch under. :data:`ACCEL_TCG` (the default)
            keeps the machine running with no accelerator; :data:`ACCEL_WHPX`
            launches paused under the Windows accelerator, for gates that must
            observe what WHPX permits.

    Yields:
        LiveQemu: The running QEMU and the image it holds.

    Raises:
        RuntimeError: If the image could not be created.
    """
    image = workdir / "monitor-target.qcow2"
    created = run_qemu_img("create", "-f", "qcow2", str(image), IMAGE_SIZE)
    if created.returncode != SUCCESS:
        message = f"could not create the target image: {created.stderr}"
        raise RuntimeError(message)

    port = bindable_port()
    process = subprocess.Popen(_live_qemu_argv(image, memory_mb, port, accel), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    running = LiveQemu(image=image, monitor_port=port, process=process)
    try:
        wait_for_monitor(port, process)
        yield running
    finally:
        running.stop()
