# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D35: the in-guest agent must listen where the host can reach it.

The Intellicrack agent inside a QEMU guest is reached through a SLIRP port
forward built by :meth:`QEMUSandbox._build_qemu_command`
(``-netdev user,...,hostfwd=tcp::<host>-:4445``). SLIRP does not hand a
forwarded connection to the guest's loopback interface: it opens the guest-side
connection to the guest's own address on the virtual network - ``10.0.2.15`` for
the default SLIRP subnet - so a listener bound to ``127.0.0.1`` inside the guest
is unreachable from the host no matter how healthy it is. The generated Windows
agent bound exactly that address, so its command channel could never work; the
generated Linux agent binds ``0.0.0.0``, which is why every live proof in this
program was obtained on a Linux guest.

The defect survived the earlier agent gates because the listener is the one
statement they do not use. S17-D26's peer lifts the generated agent's
declarations, its allowlist, its framing and both dispatch branches, but writes
its own listener so it can be given a free port. The generated listener line was
therefore never executed by anything.

Here it is. The peer this module runs is assembled from the same generated
source *including its own listener statement*, unedited, and run by a real
``powershell.exe``; the production :class:`GuestAgentClient` then handshakes
against it over a real TCP connection opened to a local address that is not
``127.0.0.1``. That is the property the guest situation reduces to - a listener
bound to one address does not serve another - and it is what a loopback-bound
listener cannot answer. Nothing here restates what the agent should bind: if the
generated statement binds loopback, the connection is refused and the gate is
red.

Three further properties are checked against the same generated sources, so the
Linux half and the forward itself are covered too:

* the address the generated Linux ``agent.py`` passes to ``bind`` must likewise
  answer a connection to that address, proven by binding a real socket to it and
  connecting;
* both generated agents must bind the same address, because they are reached
  through the same kind of forward;
* the port each agent binds must be the guest-side port of the agent
  ``hostfwd`` rule in the argv the real ``_build_qemu_command`` emits. Those
  three numbers live in three separate sources - a Python f-string, a PowerShell
  literal and a Python literal inside a generated script - with no shared
  constant to make the comparison true by construction.
"""

from __future__ import annotations

import ast
import asyncio
import ipaddress
import re
import socket
from contextlib import closing
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestAgentClient, GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.generated_agent_peer import (
    AGENT_SCRIPT_NAME,
    LISTENER_LINE,
    MONITOR_DIRECTORY,
    GeneratedAgentPeer,
    build_peer_script,
    script_line,
)


if TYPE_CHECKING:
    from pathlib import Path

_LINUX_AGENT_NAME: Final[str] = "agent.py"
_PEER_SCRIPT_NAME: Final[str] = "s17d35_peer.ps1"

_LISTENER_CONSTRUCTION: Final = re.compile(
    r"\[System\.Net\.Sockets\.TcpListener\]::new\(\s*(?P<address>.+?)\s*,\s*(?P<port>\d+)\s*\)",
)
_PARSE_CALL: Final = re.compile(r"\[System\.Net\.IPAddress\]::Parse\(\s*'(?P<literal>[^']*)'\s*\)")

_IPV4_LOOPBACK: Final[int] = 0x7F000001
# The next address after it, which the machine answers on just as readily but
# which a listener bound to the first one does not serve.
_SECONDARY_LOOPBACK: Final[str] = str(ipaddress.IPv4Address(_IPV4_LOOPBACK + 1))

# The four static fields of System.Net.IPAddress the agent could name, each
# resolved through the stdlib rather than spelled out, so the dotted-quad forms
# compared against the generated script are not this module's own opinion.
_DOTNET_ADDRESS_FIELDS: Final[dict[str, str]] = {
    "[System.Net.IPAddress]::Any": str(ipaddress.IPv4Address(0)),
    "[System.Net.IPAddress]::IPv6Any": str(ipaddress.IPv6Address(0)),
    "[System.Net.IPAddress]::Loopback": str(ipaddress.IPv4Address(_IPV4_LOOPBACK)),
    "[System.Net.IPAddress]::IPv6Loopback": str(ipaddress.IPv6Address(1)),
}

_BIND_METHOD: Final[str] = "bind"
_HOSTFWD_PREFIX: Final[str] = "hostfwd=tcp::"
_NETDEV_ARGUMENT: Final[str] = "-netdev"

_QEMU_BINARY_NAME: Final[str] = "qemu-system-x86_64.exe"
_DISK_IMAGE_NAME: Final[str] = "guest.qcow2"
_SHARE_DIRECTORY: Final[str] = "shared"
# QCOW2 magic and version 3, so the image the command line names is a real
# image file rather than an empty one.
_QCOW2_HEADER: Final[bytes] = b"QFI\xfb\x00\x00\x00\x03"

_AGENT_CONNECT_TIME_LIMIT: Final[float] = 20.0
_AGENT_CONNECT_RETRY_INTERVAL: Final[float] = 0.5
_CONNECT_TIME_LIMIT: Final[float] = 5.0
_LISTEN_BACKLOG: Final[int] = 1

_ERR_NO_CONSTRUCTION: Final[str] = "the generated agent's listener statement {statement!r} constructs no TcpListener"
_ERR_UNMODELLED_ADDRESS: Final[str] = "the generated agent binds the unmodelled .NET address expression {address!r}"
_ERR_NO_BIND: Final[str] = "the generated Linux agent calls no bind() with a literal address and a named port"
_ERR_NO_PORT_CONSTANT: Final[str] = "the generated Linux agent declares no {name} constant"
_ERR_NO_AGENT_HOSTFWD: Final[str] = "the QEMU command line forwards no host port {port} to the guest: {netdev!r}"
_ERR_NO_NETDEV: Final[str] = "the QEMU command line carries no -netdev argument"
_ERR_NO_ROUTABLE_ADDRESS: Final[str] = "this machine will not bind {address}, so no forward to it can be modelled: {error}"
_ERR_UNREACHABLE: Final[str] = "a listener bound to {bound!r} refused a connection to {target!r}: {error}"


def _delivery_address() -> str:
    """Return a local address that is not the one loopback-bound listeners serve.

    This stands in for the guest address SLIRP opens a forwarded connection to.
    What makes that address fatal to a loopback-bound listener is not that it is
    routable - it is that it is a *different* local address, and a listener bound
    to one address does not serve another. This machine's own non-loopback
    address is used when it has one; a test container is started with
    ``--network none`` and has only the loopback interface, so the second
    loopback address is used there, which discriminates the two binds exactly
    the same way. Measured in that container: a listener on the wildcard address
    accepts a connection to it, and one bound to ``127.0.0.1`` refuses it with
    ``WinError 10061``.

    Whichever is chosen is put through :func:`_local_address`, which fails the
    test rather than let a gate read "not a local address" as a verdict on what
    the agent bound.

    Returns:
        str: An address this machine answers on, other than ``127.0.0.1``.
    """
    resolved = socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    for *_, sockaddr in resolved:
        address = str(sockaddr[0])
        if not ipaddress.ip_address(address).is_loopback:
            return _local_address(address)
    return _local_address(_SECONDARY_LOOPBACK)


def _local_address(address: str) -> str:
    """Require an address to be one this machine accepts connections on.

    A listener is bound to it and closed again, which is the machine's own
    answer to whether the address is local - the gate that follows would
    otherwise read "not a local address" as "the agent bound the wrong one".

    Args:
        address: Address to check.

    Returns:
        str: The address itself.

    Raises:
        AssertionError: If the machine refuses to bind it.
    """
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as probe:
            probe.bind((address, 0))
    except OSError as e:
        raise AssertionError(_ERR_NO_ROUTABLE_ADDRESS.format(address=address, error=e)) from e
    return address


def _windows_listener_endpoint(agent_script: str) -> tuple[str, int]:
    """Read the endpoint the generated Windows agent's own listener binds.

    Args:
        agent_script: Full text of the generated ``agent.ps1``.

    Returns:
        tuple[str, int]: The address the ``TcpListener`` is constructed with,
        resolved to its dotted-quad form, and its port.

    Raises:
        AssertionError: If the listener statement constructs no ``TcpListener``,
            or constructs one from an address expression this module cannot
            resolve - which is a statement whose behaviour it must not claim to
            know.
    """
    statement = script_line(agent_script, LISTENER_LINE)
    construction = _LISTENER_CONSTRUCTION.search(statement)
    if construction is None:
        raise AssertionError(_ERR_NO_CONSTRUCTION.format(statement=statement))

    expression = construction["address"]
    literal = _DOTNET_ADDRESS_FIELDS.get(expression)
    if literal is None:
        parsed = _PARSE_CALL.fullmatch(expression)
        if parsed is None:
            raise AssertionError(_ERR_UNMODELLED_ADDRESS.format(address=expression))
        literal = parsed["literal"]
    return literal, int(construction["port"])


def _linux_listener_endpoint(agent_script: str) -> tuple[str, int]:
    """Read the endpoint the generated Linux agent's own server binds.

    Args:
        agent_script: Full text of the generated ``agent.py``.

    Returns:
        tuple[str, int]: The address literal passed to ``bind`` and the value of
        the module constant it is given as a port.

    Raises:
        AssertionError: If the agent makes no such ``bind`` call, or names a
            port constant it never declares.
    """
    tree = ast.parse(agent_script)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != _BIND_METHOD or len(node.args) != 1:
            continue
        endpoint = node.args[0]
        if not isinstance(endpoint, ast.Tuple) or len(endpoint.elts) != 2:
            continue
        address, port = endpoint.elts
        if not isinstance(address, ast.Constant) or not isinstance(address.value, str):
            continue
        if not isinstance(port, ast.Name):
            continue
        return address.value, _module_constant(tree, port.id)
    raise AssertionError(_ERR_NO_BIND)


def _module_constant(tree: ast.Module, name: str) -> int:
    """Return the integer a generated module declares under ``name``.

    Args:
        tree: Parsed generated agent module.
        name: Constant to read.

    Returns:
        int: The declared value.

    Raises:
        AssertionError: If the module declares no such integer constant.
    """
    for node in tree.body:
        if not isinstance(node, ast.AnnAssign | ast.Assign):
            continue
        targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, int):
            return value.value
    raise AssertionError(_ERR_NO_PORT_CONSTANT.format(name=name))


def _forwarded_guest_port(command: list[str], host_port: int) -> int:
    """Read the guest-side port of the agent forward from a real QEMU argv.

    Args:
        command: The argv :meth:`QEMUSandbox._build_qemu_command` emitted.
        host_port: Host-side port of the agent forward, as the sandbox
            resolved it.

    Returns:
        int: Port inside the guest that the agent forward delivers to.

    Raises:
        AssertionError: If the argv carries no ``-netdev`` argument, or none
            that forwards ``host_port``.
    """
    if _NETDEV_ARGUMENT not in command:
        raise AssertionError(_ERR_NO_NETDEV)
    netdev = command[command.index(_NETDEV_ARGUMENT) + 1]
    for option in netdev.split(","):
        if not option.startswith(_HOSTFWD_PREFIX):
            continue
        forwarded, _, guest = option.removeprefix(_HOSTFWD_PREFIX).partition("-:")
        if forwarded == str(host_port):
            return int(guest)
    raise AssertionError(_ERR_NO_AGENT_HOSTFWD.format(port=host_port, netdev=netdev))


def _assert_reachable_at(bind_address: str, target_address: str) -> None:
    """Bind a real socket and require a real connection to ``target_address``.

    Args:
        bind_address: Address the listener binds, as the generated agent binds
            it.
        target_address: Address the connection is opened to, standing in for
            the guest address SLIRP delivers a forwarded connection to.

    Raises:
        AssertionError: If the connection is refused, which is what the host
            sees when the in-guest listener is bound to loopback.
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as listener:
        listener.bind((bind_address, 0))
        listener.listen(_LISTEN_BACKLOG)
        port = int(listener.getsockname()[1])
        try:
            with closing(socket.create_connection((target_address, port), timeout=_CONNECT_TIME_LIMIT)):
                accepted, _ = listener.accept()
                accepted.close()
        except OSError as e:
            raise AssertionError(
                _ERR_UNREACHABLE.format(bound=bind_address, target=target_address, error=e),
            ) from e


class _AgentGeneratingSandbox(QEMUSandbox):
    """``QEMUSandbox`` used to generate a real agent and a real command line."""

    async def generate_agent_script(self, share: Path, name: str) -> str:
        """Generate the production in-guest agent and read it back.

        Args:
            share: Host directory standing in for the guest's shared folder.
            name: File name the agent is generated under for this guest OS.

        Returns:
            str: Full text of the generated agent script.
        """
        self._shared_folder = share
        await asyncio.to_thread((share / MONITOR_DIRECTORY).mkdir, parents=True, exist_ok=True)
        await self._create_guest_agent_script()
        return await asyncio.to_thread(
            (share / MONITOR_DIRECTORY / name).read_text,
            encoding="utf-8",
        )

    async def build_command(self, qemu_path: Path) -> tuple[list[str], int]:
        """Build the real QEMU launch command line.

        Args:
            qemu_path: Path recorded as the resolved QEMU executable, which the
                command builder refuses to run without.

        Returns:
            tuple[list[str], int]: The argv QEMU would be launched with, and the
            host-side agent port the sandbox resolved while building it.
        """
        self._qemu_path = qemu_path
        command = await self._build_qemu_command()
        return command, self._qemu_config.agent_port


def _sandbox(guest_os: GuestOS, image_path: Path | None = None) -> _AgentGeneratingSandbox:
    """Build a sandbox for one guest OS.

    Args:
        guest_os: Guest operating system the agent is generated for.
        image_path: Disk image recorded on the config so the real
            ``_build_qemu_command`` can run, or None when only the agent script
            is needed.

    Returns:
        _AgentGeneratingSandbox: Sandbox whose agent generator and command
        builder are the production ones.
    """
    return _AgentGeneratingSandbox(
        config=SandboxConfig(),
        qemu_config=QEMUConfig(guest_os=guest_os, image_path=image_path, display="none"),
    )


def _disk_image(tmp_path: Path) -> Path:
    """Create the disk image the built command line names.

    Args:
        tmp_path: Directory the image is created under.

    Returns:
        Path: A file carrying a real QCOW2 header.
    """
    image = tmp_path / _DISK_IMAGE_NAME
    image.write_bytes(_QCOW2_HEADER)
    return image


def _qemu_binary(tmp_path: Path) -> Path:
    """Create the emulator path the command builder refuses to run without.

    Args:
        tmp_path: Directory the binary is created under.

    Returns:
        Path: An existing file standing in for the resolved emulator.
    """
    binary = tmp_path / _QEMU_BINARY_NAME
    binary.write_bytes(b"")
    return binary


class TestTheGeneratedWindowsAgentListensWhereTheForwardDelivers:
    """The Windows agent's own listener must answer a non-loopback connection."""

    @pytest.mark.asyncio
    async def test_the_production_client_handshakes_over_the_forward_address(
        self,
        tmp_path: Path,
    ) -> None:
        """The generated listener must serve the address SLIRP delivers to.

        The peer runs the generated agent's own listener statement, unedited,
        under a real ``powershell.exe``. The production client then connects to
        a local address other than ``127.0.0.1`` and completes the readiness
        handshake against the generated ping branch, retrying while the peer
        starts up, which is the same retry loop production uses on a booting
        guest. A listener bound to
        ``127.0.0.1`` - what the agent used to construct - refuses that
        connection, which is exactly what a real guest did to every command the
        host ever dispatched to a Windows guest.

        Args:
            tmp_path: Directory the share and the peer script are created under.
        """
        target = _delivery_address()
        share = tmp_path / _SHARE_DIRECTORY
        sandbox = _sandbox(GuestOS.WINDOWS)
        agent_script = await sandbox.generate_agent_script(share, AGENT_SCRIPT_NAME)
        _, port = _windows_listener_endpoint(agent_script)

        peer_path = share / MONITOR_DIRECTORY / _PEER_SCRIPT_NAME
        await asyncio.to_thread(
            peer_path.write_text,
            build_peer_script(agent_script, listener_statement=script_line(agent_script, LISTENER_LINE)),
            encoding="utf-8",
        )

        peer = GeneratedAgentPeer(peer_path, port)
        await peer.start()
        client = GuestAgentClient(host=target, port=port)
        connected = False
        try:
            connected = await client.connect(
                time_limit=_AGENT_CONNECT_TIME_LIMIT,
                retry_interval=_AGENT_CONNECT_RETRY_INTERVAL,
            )
            assert connected, f"the generated Windows agent did not answer a handshake at {target}:{port}"
            assert client.is_connected
        finally:
            await client.disconnect()
            if connected:
                await peer.stop()
            else:
                await peer.abandon()


class TestBothGeneratedAgentsBindWhereTheForwardDelivers:
    """Neither generated agent may bind an address the forward cannot reach."""

    def test_the_windows_agent_address_accepts_a_non_loopback_connection(self, tmp_path: Path) -> None:
        """A real socket on the Windows agent's address must be reachable.

        Args:
            tmp_path: Directory the share is created under.
        """
        address, _ = _windows_listener_endpoint(
            asyncio.run(_sandbox(GuestOS.WINDOWS).generate_agent_script(tmp_path, AGENT_SCRIPT_NAME)),
        )
        _assert_reachable_at(address, _delivery_address())

    def test_the_linux_agent_address_accepts_a_non_loopback_connection(self, tmp_path: Path) -> None:
        """A real socket on the Linux agent's address must be reachable.

        Args:
            tmp_path: Directory the share is created under.
        """
        address, _ = _linux_listener_endpoint(
            asyncio.run(_sandbox(GuestOS.LINUX).generate_agent_script(tmp_path, _LINUX_AGENT_NAME)),
        )
        _assert_reachable_at(address, _delivery_address())

    def test_the_two_agents_bind_the_same_address(self, tmp_path: Path) -> None:
        """Both guests are reached the same way, so both must bind the same way.

        Args:
            tmp_path: Directory the two shares are created under.
        """
        windows, _ = _windows_listener_endpoint(
            asyncio.run(_sandbox(GuestOS.WINDOWS).generate_agent_script(tmp_path / "windows", AGENT_SCRIPT_NAME)),
        )
        linux, _ = _linux_listener_endpoint(
            asyncio.run(_sandbox(GuestOS.LINUX).generate_agent_script(tmp_path / "linux", _LINUX_AGENT_NAME)),
        )
        assert windows == linux, f"the Windows agent binds {windows} and the Linux agent binds {linux}"


class TestTheForwardDeliversToThePortTheAgentsBind:
    """The hostfwd rule and both agents must agree on the guest-side port."""

    @pytest.mark.asyncio
    async def test_the_windows_agent_binds_the_forwarded_port(self, tmp_path: Path) -> None:
        """The Windows listener's port must be the one the forward delivers to.

        Args:
            tmp_path: Directory the share and the disk image are created under.
        """
        sandbox = _sandbox(GuestOS.WINDOWS, _disk_image(tmp_path))
        _, port = _windows_listener_endpoint(
            await sandbox.generate_agent_script(tmp_path / _SHARE_DIRECTORY, AGENT_SCRIPT_NAME),
        )
        command, host_port = await sandbox.build_command(_qemu_binary(tmp_path))
        assert _forwarded_guest_port(command, host_port) == port

    @pytest.mark.asyncio
    async def test_the_linux_agent_binds_the_forwarded_port(self, tmp_path: Path) -> None:
        """The Linux server's port must be the one the forward delivers to.

        Args:
            tmp_path: Directory the share and the disk image are created under.
        """
        sandbox = _sandbox(GuestOS.LINUX, _disk_image(tmp_path))
        _, port = _linux_listener_endpoint(
            await sandbox.generate_agent_script(tmp_path / _SHARE_DIRECTORY, _LINUX_AGENT_NAME),
        )
        command, host_port = await sandbox.build_command(_qemu_binary(tmp_path))
        assert _forwarded_guest_port(command, host_port) == port
