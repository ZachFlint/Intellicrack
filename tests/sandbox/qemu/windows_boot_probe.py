# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared machinery for gates that boot a real Windows guest under QEMU.

Two S17 defects - the WHPX CPU model (S17-D36) and the WHPX interrupt chip
(S17-D37) - can only be gated by starting real Windows installation media and
watching what the guest actually does. Neither is observable from the command
line alone: both produce a perfectly well-formed argv that a Windows kernel
then refuses to run on. This module holds everything those gates share so the
argv under test always comes from the production builder and never from a copy.

Every helper here is host-only. The Intellicrack test container has no
hypervisor, so the tests that use these run in the host-native pass
(:mod:`tests._helpers.host_native`).
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import AcceleratorType, GuestOS, QEMUConfig, QEMUSandbox
from scripts.sandbox.provision_windows_guest import ProvisioningError, probe_iso_structure


if TYPE_CHECKING:
    from pathlib import Path


IMAGES_DIRECTORY: Final[str] = "images"
"""Directory below the bundled QEMU tree holding disk and media images."""

WHPX_ABORT_MARKER: Final[str] = "Unexpected VP exit code"
"""Substring QEMU prints when WHPX reports an unrecoverable guest exception."""

SHUTDOWN_GRACE_SECONDS: Final[float] = 20.0
"""Time allowed for a killed QEMU to release its handles and report."""

SCRATCH_DISK_SIZE: Final[str] = "64M"
"""Virtual size of a throwaway system disk the media is booted against."""

_QEMU_IMG_STEM: Final[str] = "qemu-img"
_ISO_SUFFIX: Final[str] = ".iso"
_QEMU_IMG_TIMEOUT_SECONDS: Final[float] = 60.0
_DOCKER_QUERY_TIMEOUT_SECONDS: Final[float] = 30.0

_CDROM_DRIVE_ID: Final[str] = "icboot"
_CDROM_BUS: Final[str] = "ide.0"

_QCOW2_MAGIC: Final[bytes] = b"QFI\xfb"
_QCOW2_VERSION_3: Final[bytes] = (3).to_bytes(4, "big")
_QCOW2_HEADER_PADDING: Final[int] = 64

_MONITOR_CONNECT_TIMEOUT_SECONDS: Final[float] = 10.0
_MONITOR_READ_TIMEOUT_SECONDS: Final[float] = 15.0
_MONITOR_PROMPT: Final[bytes] = b"(qemu)"
_PPM_MAGIC: Final[bytes] = b"P6"
_PPM_HEADER_FIELDS: Final[int] = 4
_RGB_CHANNELS: Final[int] = 3
_BLACK_CHANNEL_CEILING: Final[int] = 24
"""Per-channel value at or below which a pixel counts as background black.

The Windows boot logo is drawn on true black; the ceiling only absorbs the
handful of anti-aliased near-black pixels around the glyph edges.
"""


@dataclass(frozen=True)
class BootOutcome:
    """Result of watching a QEMU process for a fixed observation window.

    Attributes:
        exited: Whether QEMU terminated inside the window.
        returncode: Exit status when it terminated, otherwise ``None``.
        output: Combined stdout and stderr text QEMU produced.
    """

    exited: bool
    returncode: int | None
    output: str

    @property
    def aborted_on_whpx_exception(self) -> bool:
        """Whether QEMU died reporting an unrecoverable WHPX guest exception.

        Returns:
            bool: True when the process exited and named the WHPX exit code.
        """
        return self.exited and WHPX_ABORT_MARKER in self.output


@dataclass(frozen=True)
class RenderObservation:
    """What a guest drew on its own display during an observation window.

    Attributes:
        peak_coverage: Largest fraction of non-black pixels seen in any frame.
        crossed_after: Seconds until coverage first passed the threshold, or
            ``None`` when it never did.
        frames: Number of frames successfully captured.
        exited: Whether QEMU terminated inside the window.
        returncode: Exit status when it terminated, otherwise ``None``.
        output: Combined stdout and stderr text QEMU produced.
    """

    peak_coverage: float
    crossed_after: float | None
    frames: int
    exited: bool
    returncode: int | None
    output: str


class LauncherSandbox(QEMUSandbox):
    """Sandbox exposing the real command builder for inspection.

    The production builder and accelerator detection are private; this subclass
    adds public entry points so the gates drive the genuine code rather than a
    copy of it.
    """

    def force_accelerator(self, accelerator: AcceleratorType) -> None:
        """Record an accelerator without running hardware detection.

        Args:
            accelerator: Accelerator the command builder should select for.
        """
        self._accelerator = accelerator
        self._accelerator_cached = True

    def set_qemu_path(self, qemu_path: Path) -> None:
        """Install the resolved QEMU binary path used by the command builder.

        Args:
            qemu_path: Path recorded as the resolved QEMU executable.
        """
        self._qemu_path = qemu_path

    async def resolve_qemu_path(self) -> Path | None:
        """Locate the QEMU executable exactly as production does.

        Returns:
            Path | None: The resolved executable, or ``None`` when QEMU is not
            installed anywhere the launcher searches.
        """
        return await self._find_qemu()

    async def detect_accelerator(self) -> AcceleratorType:
        """Run the real accelerator probes against this host.

        Returns:
            AcceleratorType: The accelerator the launcher would use here.
        """
        return await self._detect_accelerator()

    def build_command(self) -> list[str]:
        """Build the full QEMU launch command line.

        Returns:
            list[str]: The argv the launcher would start QEMU with.
        """
        return asyncio.run(self._build_qemu_command())


def images_directory() -> Path:
    """Return the bundled QEMU image directory.

    Returns:
        Path: Directory the launcher's disk and media images live in.
    """
    return QEMUSandbox.TOOLS_PATH / IMAGES_DIRECTORY


def windows_install_media() -> Path | None:
    """Find bootable Windows installation media in the image directory.

    The media is discovered structurally rather than by name: every ISO in the
    directory is probed with the provisioner's own volume-descriptor and El
    Torito reader, and the first Microsoft-authored, UDF-bridged, BIOS-bootable
    image of install size is used. No file name is assumed.

    Returns:
        Path | None: The install medium, or ``None`` when the host stages none.
    """
    directory = images_directory()
    if not directory.is_dir():
        return None
    for candidate in sorted(directory.glob(f"*{_ISO_SUFFIX}")):
        try:
            structure = probe_iso_structure(candidate)
        except ProvisioningError:
            continue
        if structure.is_windows_install_candidate:
            return candidate
    return None


def running_container_ids() -> tuple[str, ...]:
    """Return the ids of containers currently running on the Docker engine.

    Windows containers and WHPX virtual machines share the Host Compute
    Service. Starting a VM while a Windows container is live has bugchecked
    this host before, so the boot gates refuse to run in that state instead of
    risking it. A missing or unreachable Docker CLI means nothing is running as
    far as this check is concerned.

    Returns:
        tuple[str, ...]: Ids of running containers, empty when there are none
        or when Docker cannot be queried.
    """
    docker = shutil.which("docker")
    if docker is None:
        return ()
    try:
        completed = subprocess.run(
            [docker, "ps", "--quiet"],
            capture_output=True,
            text=True,
            timeout=_DOCKER_QUERY_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ()
    if completed.returncode != 0:
        return ()
    return tuple(line.strip() for line in completed.stdout.splitlines() if line.strip())


def make_scratch_disk(qemu_path: Path, destination: Path) -> Path:
    """Create a real, empty qcow2 system disk with the bundled ``qemu-img``.

    A missing ``qemu-img``, a non-zero exit status, or a missing result file
    each fail the calling test rather than being reported: none of them can
    happen beside a QEMU the launcher just resolved, so each would be a real
    defect in the bundled tool tree.

    Args:
        qemu_path: Resolved QEMU executable; ``qemu-img`` sits beside it.
        destination: Path the new image is written to.

    Returns:
        Path: The created image.
    """
    qemu_img = qemu_path.with_name(f"{_QEMU_IMG_STEM}{qemu_path.suffix}")
    assert qemu_img.is_file(), f"qemu-img not found beside {qemu_path}"
    completed = subprocess.run(
        [str(qemu_img), "create", "-f", "qcow2", str(destination), SCRATCH_DISK_SIZE],
        capture_output=True,
        text=True,
        timeout=_QEMU_IMG_TIMEOUT_SECONDS,
        check=False,
    )
    assert completed.returncode == 0, f"qemu-img create failed ({completed.returncode}): {completed.stdout}{completed.stderr}"
    assert destination.is_file(), f"qemu-img reported success but {destination} does not exist"
    return destination


def argument_value(argv: list[str], option: str) -> str:
    """Return the value following an option in a QEMU command line.

    An absent option, or one with no value after it, fails the calling test:
    the launcher emits both unconditionally, so either would mean the command
    line no longer describes a machine.

    Args:
        argv: Full QEMU argv.
        option: Option whose value is wanted, such as ``-cpu``.

    Returns:
        str: The value immediately following the option.
    """
    assert option in argv, f"{option} missing from launch command {argv}"
    index = argv.index(option)
    assert index + 1 < len(argv), f"{option} is the last argument of {argv}"
    return argv[index + 1]


def replace_argument_value(argv: list[str], option: str, value: str) -> list[str]:
    """Return a copy of a command line with one option's value replaced.

    Args:
        argv: Full QEMU argv.
        option: Option whose value is replaced.
        value: Replacement value.

    Returns:
        list[str]: A new argv carrying the replacement.
    """
    replaced = list(argv)
    replaced[replaced.index(option) + 1] = value
    return replaced


def with_boot_media(argv: list[str], media: Path) -> list[str]:
    """Append install media and a one-shot CD boot order to a command line.

    Args:
        argv: Full QEMU argv from the launcher.
        media: ISO image to attach as the boot CD.

    Returns:
        list[str]: A new argv that boots the medium once.
    """
    return [
        *argv,
        "-drive",
        f"id={_CDROM_DRIVE_ID},file={media},media=cdrom,if=none,format=raw,readonly=on",
        "-device",
        f"ide-cd,drive={_CDROM_DRIVE_ID},bus={_CDROM_BUS}",
        "-boot",
        "order=c,once=d,menu=off",
    ]


def with_monitor(argv: list[str], port: int) -> list[str]:
    """Append a TCP human monitor to a command line.

    Args:
        argv: Full QEMU argv.
        port: Loopback port the monitor listens on.

    Returns:
        list[str]: A new argv carrying the monitor.
    """
    return [*argv, "-monitor", f"tcp:127.0.0.1:{port},server=on,wait=off"]


def free_tcp_port() -> int:
    """Reserve and release a loopback TCP port.

    Returns:
        int: A port number that was free at the moment of the call.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _read_until_prompt(sock: socket.socket) -> bytes:
    """Read from the QEMU monitor until its prompt appears.

    Args:
        sock: Connected monitor socket.

    Returns:
        bytes: Everything read, including the prompt.
    """
    buffered = b""
    while _MONITOR_PROMPT not in buffered:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buffered += chunk
    return buffered


def capture_screen(monitor_port: int, destination: Path) -> bool:
    """Ask QEMU to dump the guest's current framebuffer to a PPM file.

    Args:
        monitor_port: Port the guest's human monitor listens on.
        destination: Path QEMU writes the PPM to.

    Returns:
        bool: True when a readable PPM was produced.
    """
    try:
        sock = socket.create_connection(("127.0.0.1", monitor_port), timeout=_MONITOR_CONNECT_TIMEOUT_SECONDS)
    except OSError:
        return False
    try:
        sock.settimeout(_MONITOR_READ_TIMEOUT_SECONDS)
        _read_until_prompt(sock)
        sock.sendall(f"screendump {destination.as_posix()}\n".encode())
        _read_until_prompt(sock)
    except OSError:
        return False
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return destination.is_file() and destination.stat().st_size > 0


def monitor_query(monitor_port: int, command: str) -> str:
    """Run one human-monitor command and return what the monitor printed.

    The monitor echoes each keystroke back with terminal control sequences, so
    the reply carries the command itself several times over. Callers should look
    for a substring rather than parse the text as lines.

    Args:
        monitor_port: Port the guest's human monitor listens on.
        command: Monitor command to run.

    Returns:
        str: The monitor's output, or an empty string if it could not be read.
    """
    try:
        sock = socket.create_connection(("127.0.0.1", monitor_port), timeout=_MONITOR_CONNECT_TIMEOUT_SECONDS)
    except OSError:
        return ""
    try:
        sock.settimeout(_MONITOR_READ_TIMEOUT_SECONDS)
        _read_until_prompt(sock)
        sock.sendall(f"{command}\n".encode())
        answer = _read_until_prompt(sock)
    except OSError:
        return ""
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return answer.decode("utf-8", "replace")


def non_black_coverage(ppm_path: Path) -> float:
    """Return the fraction of a PPM frame that is not background black.

    A Windows guest stopped at its boot logo covers well under one percent of
    the screen; one that has reached a real user interface covers most of it.
    The two are an order of magnitude apart, so this is a decisive reading of
    "did the guest render anything", not a heuristic about *what* it rendered.

    Args:
        ppm_path: Binary PPM (P6) file written by ``screendump``.

    Returns:
        float: Non-black pixels as a fraction of all pixels, or ``0.0`` when
        the file is not a parseable P6 frame.
    """
    data = ppm_path.read_bytes()
    if not data.startswith(_PPM_MAGIC):
        return 0.0
    fields: list[bytes] = []
    offset = 0
    while len(fields) < _PPM_HEADER_FIELDS and offset < len(data):
        while offset < len(data) and data[offset : offset + 1].isspace():
            offset += 1
        start = offset
        while offset < len(data) and not data[offset : offset + 1].isspace():
            offset += 1
        fields.append(data[start:offset])
    if len(fields) < _PPM_HEADER_FIELDS:
        return 0.0
    offset += 1
    pixels = data[offset:]
    total = len(pixels) // _RGB_CHANNELS
    if total == 0:
        return 0.0
    lit = sum(1 for value in pixels if value > _BLACK_CHANNEL_CEILING)
    return lit / (total * _RGB_CHANNELS)


def observe_boot(argv: list[str], window_seconds: float) -> BootOutcome:
    """Start QEMU and watch it for a fixed window.

    Args:
        argv: Full QEMU argv to launch.
        window_seconds: How long to wait before declaring the machine alive.

    Returns:
        BootOutcome: Whether QEMU exited inside the window, its status, and
        everything it wrote to stdout and stderr.
    """
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
        try:
            output, _ = process.communicate(timeout=window_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=SHUTDOWN_GRACE_SECONDS)
            return BootOutcome(exited=False, returncode=None, output=output or "")
        return BootOutcome(exited=True, returncode=process.returncode, output=output or "")


def observe_rendering(
    argv: list[str],
    monitor_port: int,
    frame_directory: Path,
    *,
    window_seconds: float,
    coverage_threshold: float,
    sample_interval_seconds: float,
) -> RenderObservation:
    """Start QEMU and sample the guest's framebuffer until it renders a UI.

    Sampling stops as soon as coverage passes the threshold, so a guest that
    boots normally costs only as long as it takes to get there; a guest that
    never renders costs the full window.

    Args:
        argv: Full QEMU argv to launch. Must already carry a human monitor.
        monitor_port: Port that monitor listens on.
        frame_directory: Directory the sampled PPM frames are written to.
        window_seconds: Longest time to keep sampling.
        coverage_threshold: Non-black fraction that counts as a rendered UI.
        sample_interval_seconds: Delay between samples.

    Returns:
        RenderObservation: Peak coverage, when the threshold was crossed, and
        the process outcome.
    """
    peak = 0.0
    crossed: float | None = None
    frames = 0
    started = time.monotonic()
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
        while time.monotonic() - started < window_seconds:
            time.sleep(sample_interval_seconds)
            if process.poll() is not None:
                break
            frame = frame_directory / f"frame-{frames:03d}.ppm"
            if not capture_screen(monitor_port, frame):
                continue
            frames += 1
            coverage = non_black_coverage(frame)
            peak = max(peak, coverage)
            if coverage >= coverage_threshold:
                crossed = time.monotonic() - started
                break
        exited = process.poll() is not None
        if not exited:
            process.kill()
        output, _ = process.communicate(timeout=SHUTDOWN_GRACE_SECONDS)
    return RenderObservation(
        peak_coverage=peak,
        crossed_after=crossed,
        frames=frames,
        exited=exited,
        returncode=process.returncode if exited else None,
        output=output or "",
    )


def empty_qcow2(destination: Path) -> Path:
    """Write a minimal but structurally valid qcow2 v3 header file.

    ``_build_qemu_command`` only requires the configured image to exist; it
    never parses it. A real header is written anyway so the fixture is a genuine
    qcow2 rather than arbitrary bytes.

    Args:
        destination: Path the header is written to.

    Returns:
        Path: The created file.
    """
    destination.write_bytes(_QCOW2_MAGIC + _QCOW2_VERSION_3 + bytes(_QCOW2_HEADER_PADDING))
    return destination


def launcher_argv_for(accelerator: AcceleratorType, image: Path, qemu_path: Path) -> list[str]:
    """Build the launcher command line for one accelerator without hardware.

    Args:
        accelerator: Accelerator the command builder should select for.
        image: Existing disk image recorded on the configuration.
        qemu_path: Path recorded as the resolved QEMU executable.

    Returns:
        list[str]: The argv the production builder emits.
    """
    config = QEMUConfig(guest_os=GuestOS.WINDOWS, image_path=image, display="none")
    sandbox = LauncherSandbox(config=SandboxConfig(), qemu_config=config)
    sandbox.force_accelerator(accelerator)
    sandbox.set_qemu_path(qemu_path)
    return sandbox.build_command()


def whpx_launcher_argv(image: Path) -> list[str]:
    """Build the launcher command line for a WHPX Windows guest.

    Args:
        image: Real qcow2 system disk the launcher boots.

    Returns:
        list[str]: The argv the production builder emits for this guest.
    """
    config = QEMUConfig(guest_os=GuestOS.WINDOWS, image_path=image, display="none")
    sandbox = LauncherSandbox(config=SandboxConfig(), qemu_config=config)
    sandbox.force_accelerator(AcceleratorType.WHPX)
    qemu_path = asyncio.run(sandbox.resolve_qemu_path())
    assert qemu_path is not None, "QEMU executable not found by the launcher's own search"
    sandbox.set_qemu_path(qemu_path)
    return sandbox.build_command()


def resolve_whpx_qemu_path() -> tuple[Path | None, str]:
    """Resolve the QEMU executable and confirm this host runs WHPX.

    Returns:
        tuple[Path | None, str]: The executable and an empty string when the
        host can run these gates, or ``None`` and the reason it cannot.
    """
    config = QEMUConfig(guest_os=GuestOS.WINDOWS, display="none")
    sandbox = LauncherSandbox(config=SandboxConfig(), qemu_config=config)
    qemu_path = asyncio.run(sandbox.resolve_qemu_path())
    if qemu_path is None:
        return None, "QEMU is not installed on this host"
    sandbox.set_qemu_path(qemu_path)
    accelerator = asyncio.run(sandbox.detect_accelerator())
    if accelerator != AcceleratorType.WHPX:
        return None, f"host accelerator is {accelerator.value}; these gates cover WHPX-specific defects"
    running = running_container_ids()
    if running:
        return None, f"{len(running)} Docker container(s) running; Windows containers and WHPX share the Host Compute Service"
    return qemu_path, ""
