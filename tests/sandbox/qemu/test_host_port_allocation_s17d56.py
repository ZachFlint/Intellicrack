# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D56: QEMU's host ports must be allocated, and verified bindable.

``QEMUConfig`` used to fix ``ssh_port=2222``, ``monitor_port=4444`` and
``agent_port=4445``, with the guest-agent channel derived one above the last.
``_build_qemu_command`` read ``config.ssh_port or self._get_free_port()``, so
the allocator behind that ``or`` could never run on a default configuration.
Two things followed.

Two QEMU sandboxes could never run at once - the second asked for the same four
numbers and lost - which made ``SandboxBridge.diff``, a comparison of two runs,
structurally unreachable on this backend.

And the fixed ports were not dependably bindable. Windows reserves TCP ranges
for Hyper-V that carry no listener at all and still refuse a bind with
``WSAEACCES``, and it redraws them at every boot. On the host this was found on,
a reboot put 2208-2307 in that set, so QEMU answered ``Could not set up host
forwarding rule 'tcp::2222-:22'`` and the sandbox could not start at all.

That is also why the freeness probe had to change instrument rather than just
be called more often. ``_port_is_free`` was a ``connect_ex`` probe, which asks
whether anyone is listening - a different question from whether a bind will
succeed, and it answers "free" for every reserved range. The tests below pin
the distinction with a socket that is bound and never listened on, which is the
same disagreement between the two instruments, reproducible on any host and
without needing a Hyper-V reservation to exist.

Nothing here is a double of the code under test: the ports come out of the real
argv that ``_build_qemu_command`` hands to QEMU, and every assertion about
whether a port is usable is settled by binding it for real.
"""

from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.types import SandboxError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
)


if TYPE_CHECKING:
    from pathlib import Path


_VNC_PORT_BASE: Final[int] = 5900
_QGA_CHANNEL_OFFSET: Final[int] = 1
_QEMU_FAILURE_RETURNCODE: Final[int] = 1

# QEMU's own words, copied from the run that exposed this defect.
_HOSTFWD_FAILURE_STDERR: Final[bytes] = (
    b"qemu-system-x86_64.exe: -netdev user,id=net0,hostfwd=tcp::2222-:22,"
    b"hostfwd=tcp::4445-:4445: Could not set up host forwarding rule 'tcp::2222-:22'\r\n"
)
_UNRELATED_FAILURE_STDERR: Final[bytes] = b"qemu-system-x86_64.exe: -drive: could not open disk image\r\n"

_PINNED_SSH_PORT: Final[int] = 24571
_PINNED_MONITOR_PORT: Final[int] = 24573
_PINNED_AGENT_PORT: Final[int] = 24575


class _PortTestSandbox(QEMUSandbox):
    """Expose the internals a host-port gate has to reach.

    ``_build_qemu_command`` is the only place host ports are decided, so the
    gate drives it directly and reads the ports back out of the argv it
    produced rather than out of any intermediate the production code keeps.
    """

    def prepare(self, config: QEMUConfig, temp_dir: Path) -> None:
        """Put the sandbox in the state ``_build_qemu_command`` expects.

        Args:
            config: QEMU configuration under test.
            temp_dir: Directory standing in for the instance's temp area.
        """
        self._qemu_config = config
        self._qemu_path = temp_dir / "qemu-system-x86_64"
        self._temp_dir = temp_dir
        self._accelerator = AcceleratorType.TCG

    async def build_command(self) -> list[str]:
        """Build the QEMU argv.

        Returns:
            list[str]: The command line QEMU would be launched with.
        """
        return await self._build_qemu_command()

    async def clean_up(self) -> None:
        """Run the sandbox's own teardown."""
        await self._cleanup()

    @property
    def resolved_config(self) -> QEMUConfig:
        """The configuration as the command builder left it.

        Returns:
            QEMUConfig: Configuration carrying whatever ports were resolved.
        """
        return self._qemu_config

    @property
    def claimed_ports(self) -> set[int]:
        """The host ports this sandbox allocated.

        Returns:
            set[int]: Ports reserved on this sandbox's behalf.
        """
        return set(self._claimed_host_ports)

    @classmethod
    def probe_port(cls, port: int) -> bool:
        """Call the production freeness probe.

        Args:
            port: Port to probe.

        Returns:
            bool: What the production probe decided.
        """
        return cls._port_is_free(port)

    @classmethod
    def reserved_ports(cls) -> set[int]:
        """Return the process-wide reservation set.

        Returns:
            set[int]: Every port currently reserved by any sandbox.
        """
        return set(cls._reserved_host_ports)

    @classmethod
    def claim_port(cls) -> int:
        """Claim one host port through the production allocator.

        Returns:
            int: The claimed port.
        """
        return cls._claim_free_port(1)

    @classmethod
    def release_port(cls, port: int) -> None:
        """Return a claimed host port to the production allocator.

        Args:
            port: Port to release.
        """
        cls._release_host_ports({port})

    @classmethod
    def check_started(cls, returncode: int, stderr: bytes) -> None:
        """Run the production launch check.

        Args:
            returncode: Exit status QEMU reported.
            stderr: Bytes QEMU wrote to standard error.
        """
        cls._check_qemu_started(returncode, stderr)


def _make_sandbox() -> _PortTestSandbox:
    """Build a sandbox whose only interesting behaviour is port allocation.

    Returns:
        _PortTestSandbox: A sandbox ready for :meth:`_PortTestSandbox.prepare`.
    """
    return _PortTestSandbox(SandboxConfig(timeout_seconds=60), QEMUConfig())


def _make_config(image: Path, ssh_port: int = 0, monitor_port: int = 0, agent_port: int = 0) -> QEMUConfig:
    """Build a QEMU configuration pointed at a disk image.

    Args:
        image: Disk image path the command builder requires to exist.
        ssh_port: Explicit SSH forward pin, or zero to allocate.
        monitor_port: Explicit QMP monitor pin, or zero to allocate.
        agent_port: Explicit agent forward pin, or zero to allocate.

    Returns:
        QEMUConfig: Configuration for the command builder.
    """
    return QEMUConfig(
        guest_os=GuestOS.WINDOWS,
        image_path=image,
        display="vnc",
        ssh_port=ssh_port,
        monitor_port=monitor_port,
        agent_port=agent_port,
    )


def _write_image(tmp_path: Path, name: str) -> Path:
    """Create a file that can stand in for a qcow2 image.

    The command builder only requires the path to exist; nothing in this module
    boots it.

    Args:
        tmp_path: Pytest temp directory.
        name: File name to create.

    Returns:
        Path: The created file.
    """
    image = tmp_path / name
    image.write_bytes(b"\x00" * 512)
    return image


def _argv_value(argv: list[str], flag: str) -> str:
    """Return the value following a QEMU flag.

    Args:
        argv: The built command line.
        flag: Flag whose value is wanted.

    Returns:
        str: The argument after the flag.

    Raises:
        AssertionError: If the flag is absent.
    """
    for index, item in enumerate(argv):
        if item == flag:
            return argv[index + 1]
    message = f"{flag} missing from the QEMU command line: {argv}"
    raise AssertionError(message)


def _host_ports(argv: list[str]) -> dict[str, int]:
    """Extract every host-side TCP port from a built QEMU command line.

    These are the four sockets QEMU binds on the host: the two SLIRP forwards,
    the QMP monitor, the guest-agent chardev, and the VNC display.

    Args:
        argv: The built command line.

    Returns:
        dict[str, int]: Port per role.
    """
    netdev = _argv_value(argv, "-netdev")
    forwards = [part for part in netdev.split(",") if part.startswith("hostfwd=")]
    ssh_forward, agent_forward = forwards[0], forwards[1]

    chardev = _argv_value(argv, "-chardev")
    channel = next(part for part in chardev.split(",") if part.startswith("port="))

    return {
        "ssh": int(ssh_forward.removeprefix("hostfwd=tcp::").split("-")[0]),
        "agent": int(agent_forward.removeprefix("hostfwd=tcp::").split("-")[0]),
        "monitor": int(_argv_value(argv, "-qmp").split(",")[0].rsplit(":", 1)[1]),
        "channel": int(channel.removeprefix("port=")),
        "vnc": int(_argv_value(argv, "-vnc").removeprefix(":")) + _VNC_PORT_BASE,
    }


def _bind_without_listening(port: int) -> socket.socket:
    """Occupy a port the way a socket that never accepts anything does.

    Args:
        port: Port to bind.

    Returns:
        socket.socket: The bound socket, which the caller must close.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", port))
    return sock


def _connect_probe_says_free(port: int) -> bool:
    """Answer the question the superseded probe asked.

    This is the discriminator, not a restatement of the code under test: it is
    the *old* implementation, kept so the tests can show the two instruments
    genuinely disagree about the same port.

    Args:
        port: Port to probe.

    Returns:
        bool: True when nothing is listening on the port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex(("127.0.0.1", port)) != 0


class TestThePortProbeAsksWhetherItCanBind:
    """The probe must predict QEMU's bind, not survey listeners."""

    def test_a_port_bound_without_a_listener_is_not_free(self) -> None:
        """A bound-but-unlistened port is unusable, and the old probe missed it.

        This is the exact shape of a Windows reserved range - no listener, no
        connection possible, and a bind that fails anyway - reproduced without
        depending on the host having one.
        """
        port = _PortTestSandbox.claim_port()
        occupied = _bind_without_listening(port)
        try:
            assert _connect_probe_says_free(port), (
                "the discriminator is broken: a socket that never listens should still refuse connections"
            )
            assert not _PortTestSandbox.probe_port(port), f"port {port} is bound and cannot be bound again, but the probe called it free"
        finally:
            occupied.close()
            _PortTestSandbox.release_port(port)

    def test_an_unused_port_is_free(self) -> None:
        """A port nothing holds must probe as usable.

        Without this, a probe that always answered False would pass the test
        above while making the allocator unable to find any port at all.
        """
        port = _PortTestSandbox.claim_port()
        try:
            assert _PortTestSandbox.probe_port(port), f"nothing holds port {port}, yet the probe called it unusable"
        finally:
            _PortTestSandbox.release_port(port)


class TestTwoSandboxesGetPortsNeitherHasToFightFor:
    """Compare-two-runs needs two live instances, so their ports must differ."""

    def test_two_default_configurations_produce_disjoint_host_ports(self, tmp_path: Path) -> None:
        """No host port may appear in both sandboxes' command lines.

        Args:
            tmp_path: Pytest temp directory.
        """
        first, second = _make_sandbox(), _make_sandbox()
        first.prepare(_make_config(_write_image(tmp_path, "a.qcow2")), tmp_path / "a")
        second.prepare(_make_config(_write_image(tmp_path, "b.qcow2")), tmp_path / "b")

        first_ports = _host_ports(asyncio.run(first.build_command()))
        second_ports = _host_ports(asyncio.run(second.build_command()))

        shared = set(first_ports.values()) & set(second_ports.values())
        assert not shared, f"both sandboxes were given host port(s) {sorted(shared)}: {first_ports} vs {second_ports}"

    def test_every_host_port_on_the_command_line_can_be_bound(self, tmp_path: Path) -> None:
        """Each port handed to QEMU must be one the host will actually grant.

        Args:
            tmp_path: Pytest temp directory.

        Raises:
            AssertionError: If any port on the command line cannot be bound.
        """
        sandbox = _make_sandbox()
        sandbox.prepare(_make_config(_write_image(tmp_path, "disk.qcow2")), tmp_path / "run")
        ports = _host_ports(asyncio.run(sandbox.build_command()))

        held: list[socket.socket] = []
        try:
            for role, port in ports.items():
                try:
                    held.append(_bind_without_listening(port))
                except OSError as error:
                    message = f"QEMU would be launched with an unbindable {role} port {port}: {error}"
                    raise AssertionError(message) from error
        finally:
            for sock in held:
                sock.close()

    def test_the_guest_agent_channel_port_is_allocated_and_not_merely_derived(self, tmp_path: Path) -> None:
        """The chardev sits one above the agent port, so both must be claimed.

        Args:
            tmp_path: Pytest temp directory.
        """
        sandbox = _make_sandbox()
        sandbox.prepare(_make_config(_write_image(tmp_path, "disk.qcow2")), tmp_path / "run")
        ports = _host_ports(asyncio.run(sandbox.build_command()))

        assert ports["channel"] == ports["agent"] + _QGA_CHANNEL_OFFSET, (
            f"the chardev port {ports['channel']} is not one above the agent port {ports['agent']}"
        )
        claimed = sandbox.claimed_ports
        assert ports["channel"] in claimed, (
            f"the chardev port {ports['channel']} was derived but never reserved, so another sandbox may take it: {claimed}"
        )


class TestAPinnedPortIsUsedExactlyAsGiven:
    """An explicitly configured port is the caller's decision, not a hint."""

    def test_configured_ports_reach_the_command_line_unchanged(self, tmp_path: Path) -> None:
        """Pinned ports must not be replaced by allocated ones.

        Args:
            tmp_path: Pytest temp directory.
        """
        sandbox = _make_sandbox()
        sandbox.prepare(
            _make_config(
                _write_image(tmp_path, "disk.qcow2"),
                ssh_port=_PINNED_SSH_PORT,
                monitor_port=_PINNED_MONITOR_PORT,
                agent_port=_PINNED_AGENT_PORT,
            ),
            tmp_path / "run",
        )
        ports = _host_ports(asyncio.run(sandbox.build_command()))

        assert ports["ssh"] == _PINNED_SSH_PORT, f"pinned ssh port was replaced by {ports['ssh']}"
        assert ports["monitor"] == _PINNED_MONITOR_PORT, f"pinned monitor port was replaced by {ports['monitor']}"
        assert ports["agent"] == _PINNED_AGENT_PORT, f"pinned agent port was replaced by {ports['agent']}"


class TestABindFailureIsReportedAsOne:
    """A bare ``QEMU start failed`` tells an operator nothing about a reserved range."""

    def test_a_host_forwarding_failure_names_the_port_problem(self) -> None:
        """The raised error must carry QEMU's text and the port explanation."""
        with pytest.raises(SandboxError) as failure:
            _PortTestSandbox.check_started(_QEMU_FAILURE_RETURNCODE, _HOSTFWD_FAILURE_STDERR)

        message = str(failure.value)
        assert "excludedportrange" in message, f"the error does not tell the operator how to inspect reservations: {message}"
        assert "Could not set up host forwarding rule" in message, f"QEMU's own diagnosis was dropped: {message}"

    def test_an_unrelated_failure_is_not_blamed_on_ports(self) -> None:
        """A failure that is not a bind must not claim to be one."""
        with pytest.raises(SandboxError) as failure:
            _PortTestSandbox.check_started(_QEMU_FAILURE_RETURNCODE, _UNRELATED_FAILURE_STDERR)

        assert "excludedportrange" not in str(failure.value), f"a disk-image failure was reported as a host-port problem: {failure.value}"


class TestPortsComeBackWhenTheSandboxIsTornDown:
    """A long-lived process must not leak the range it allocates from."""

    def test_cleanup_releases_the_reservation_and_rearms_allocation(self, tmp_path: Path) -> None:
        """After teardown the ports are free again and the config re-allocates.

        Args:
            tmp_path: Pytest temp directory.
        """
        sandbox = _make_sandbox()
        sandbox.prepare(_make_config(_write_image(tmp_path, "disk.qcow2")), tmp_path / "run")
        ports = set(_host_ports(asyncio.run(sandbox.build_command())).values())

        assert ports <= _PortTestSandbox.reserved_ports(), f"allocated ports {sorted(ports)} were never recorded as reserved"

        asyncio.run(sandbox.clean_up())

        still_held = ports & _PortTestSandbox.reserved_ports()
        assert not still_held, f"teardown leaked host port(s) {sorted(still_held)}"

        config = sandbox.resolved_config
        assert (config.ssh_port, config.monitor_port, config.agent_port) == (0, 0, 0), (
            "a released port is still pinned in the configuration, so a restart would reuse a port another sandbox may hold: "
            f"ssh={config.ssh_port} monitor={config.monitor_port} agent={config.agent_port}"
        )
