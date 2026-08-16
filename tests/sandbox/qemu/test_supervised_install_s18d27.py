# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gates for S18-D27: the printed install command could not finish an install.

``print_plan`` told the operator to *"Run this command to perform the
unattended install"*, and that single command provably cannot. Windows Setup
power cycles the guest between its phases and QEMU exits when it does: three
real runs of the 26100 media ended ``rc=0`` partway through, on two different
command lines, one of them without any ``-boot once=`` element at all. The
disk is left mid-install. Relaunching the guest off its system disk carried
the same installation to a booted Windows whose agent answered
``guest-sync-delimited`` 338 seconds later.

The provisioner now supervises the sequence rather than describing one boot of
it. These gates drive that supervisor for real - real subprocesses, real
loopback sockets, real agent framing - against a stand-in guest that
reproduces the host-visible shape of the power cycle. Everything under test is
production code; only the hypervisor is stood in for, because a Windows guest
and an hour of wall clock are not available to a test host.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
from pathlib import Path
from typing import Final, cast

import pytest

from scripts.sandbox.provision_windows_guest import (
    InstallCommandSpec,
    ProvisioningError,
    agent_channel_port,
    build_install_command,
    build_resume_command,
    guest_agent_responds,
    run_unattended_install,
)
from tests.sandbox.qemu import power_cycling_guest
from tests.sandbox.qemu.power_cycling_guest import (
    ANSWER_ON_BOOT_VARIABLE,
    BOOT_LOG_VARIABLE,
    BOOT_SECONDS_VARIABLE,
)


_GUEST_SCRIPT: Final[Path] = Path(power_cycling_guest.__file__)

_BOOT_ARGUMENT: Final[str] = "-boot"
_ONCE_ELEMENT: Final[str] = "once="

_UNUSED_VNC_PORT: Final[int] = 5900
_CANDIDATE_AGENT_PORTS: Final[range] = range(24_000, 24_120)

_PROBE_TIMEOUT_SECONDS: Final[float] = 1.5
_SERVER_LIFETIME_SECONDS: Final[float] = 8.0
_JOIN_TIMEOUT_SECONDS: Final[float] = 10.0
_SHUTDOWN_GRACE_SECONDS: Final[float] = 20.0
_SUPERVISION_BUDGET_SECONDS: Final[float] = 180.0
_POLL_SECONDS: Final[float] = 0.5
_FOREIGN_TOKEN: Final[int] = 999_999
_READ_SIZE: Final[int] = 4096
_SYNC_DELIMITER: Final[bytes] = b"\xff"

_EXPECTED_POWER_CYCLES: Final[int] = 1
_RESTART_LIMIT: Final[int] = 2
_EXPECTED_GIVE_UP_BOOTS: Final[int] = 3


def _install_argv(tmp_path: Path, agent_port: int) -> tuple[str, ...]:
    """Build a real install argv whose executable is the stand-in guest.

    The vector comes from :func:`build_install_command`, so its boot order and
    its agent channel are the ones the provisioner really emits.

    Args:
        tmp_path: Per-test temporary directory.
        agent_port: Base agent port handed to the command builder.

    Returns:
        tuple[str, ...]: Argument vector, interpreter first.
    """
    spec = InstallCommandSpec(
        qemu_executable=Path(sys.executable),
        accelerator="tcg",
        cpu_cores=2,
        memory_mb=2048,
        disk_image=tmp_path / "guest.qcow2",
        install_iso=tmp_path / "windows.iso",
        answer_iso=tmp_path / "answer.iso",
        virtio_iso=tmp_path / "virtio.iso",
        display="none",
        vnc_port=_UNUSED_VNC_PORT,
        agent_port=agent_port,
    )
    command = build_install_command(spec)
    return (command[0], str(_GUEST_SCRIPT), *command[1:])


def _bindable(port: int) -> bool:
    """Report whether a loopback port can be bound right now.

    Args:
        port: TCP port to try.

    Returns:
        bool: True when the bind succeeded.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def _argv_with_free_channel(tmp_path: Path) -> tuple[str, ...]:
    """Build an install argv whose derived agent channel port is free.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        tuple[str, ...]: Argument vector, interpreter first.

    Raises:
        AssertionError: If no candidate port was free.
    """
    for agent_port in _CANDIDATE_AGENT_PORTS:
        command = _install_argv(tmp_path, agent_port)
        if _bindable(agent_channel_port(command)):
            return command
    message = f"no free agent channel across {_CANDIDATE_AGENT_PORTS}"
    raise AssertionError(message)


def _argument_value(vector: tuple[str, ...], name: str) -> str:
    """Return the value following an argument in a vector.

    Args:
        vector: Argument vector.
        name: Argument whose value is wanted.

    Returns:
        str: The following element, or the empty string when absent.
    """
    for index, argument in enumerate(vector[:-1]):
        if argument == name:
            return vector[index + 1]
    return ""


def _recorded_boots(log: Path) -> list[tuple[str, ...]]:
    """Return every argument vector the stand-in guest was launched with.

    Args:
        log: Boot log written by the stand-in guest.

    Returns:
        list[tuple[str, ...]]: One vector per boot, in order.
    """
    if not log.is_file():
        return []
    boots: list[tuple[str, ...]] = []
    for line in log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        decoded: object = json.loads(line)
        if isinstance(decoded, list):
            boots.append(tuple(str(argument) for argument in cast("list[object]", decoded)))
    return boots


def test_the_resume_argv_stops_booting_the_installation_medium(tmp_path: Path) -> None:
    """Replaying the install argv verbatim would restart the installation.

    Args:
        tmp_path: Per-test temporary directory.
    """
    command = _install_argv(tmp_path, _CANDIDATE_AGENT_PORTS.start)

    resumed = build_resume_command(command)

    installing = _argument_value(command, _BOOT_ARGUMENT)
    assert _ONCE_ELEMENT in installing, f"the install argv boots {installing!r}, so this run cannot show the resume argv dropping anything"
    resuming = _argument_value(resumed, _BOOT_ARGUMENT)
    assert _ONCE_ELEMENT not in resuming, f"the resumed guest would boot the installation medium again via {resuming!r}"
    assert "order=c" in resuming, f"the resumed guest has no system disk in its boot order: {resuming!r}"
    differences = [(before, after) for before, after in zip(command, resumed, strict=True) if before != after]
    assert differences == [(installing, resuming)], f"resuming changed more of the machine than its boot order: {differences}"


def test_an_accepting_channel_is_not_a_running_guest_agent(tmp_path: Path) -> None:
    """QEMU binds the channel long before the guest has an agent on it.

    Args:
        tmp_path: Per-test temporary directory.
    """
    command = _argv_with_free_channel(tmp_path)
    port = agent_channel_port(command)

    silent = threading.Thread(
        target=power_cycling_guest.serve,
        args=(port,),
        kwargs={"answer": False, "lifetime": _SERVER_LIFETIME_SECONDS},
        daemon=True,
    )
    silent.start()
    try:
        assert not guest_agent_responds(port, timeout=_PROBE_TIMEOUT_SECONDS), (
            "a channel that only accepts connections was taken for a running guest agent"
        )
    finally:
        silent.join(timeout=_JOIN_TIMEOUT_SECONDS)

    foreign = threading.Thread(target=_serve_foreign_token, args=(port,), daemon=True)
    foreign.start()
    try:
        assert not guest_agent_responds(port, timeout=_PROBE_TIMEOUT_SECONDS), (
            "a reply carrying somebody else's synchronisation id was accepted"
        )
    finally:
        foreign.join(timeout=_JOIN_TIMEOUT_SECONDS)

    answering = threading.Thread(
        target=power_cycling_guest.serve,
        args=(port,),
        kwargs={"answer": True, "lifetime": _SERVER_LIFETIME_SECONDS},
        daemon=True,
    )
    answering.start()
    try:
        assert guest_agent_responds(port, timeout=_PROBE_TIMEOUT_SECONDS), (
            "an agent echoing the synchronisation id was not recognised, so the probe can never succeed"
        )
    finally:
        answering.join(timeout=_JOIN_TIMEOUT_SECONDS)


def _serve_foreign_token(port: int) -> None:
    """Answer one synchronisation with an identifier the caller never sent.

    Args:
        port: TCP port to bind on loopback.
    """
    reply = _SYNC_DELIMITER + json.dumps({"return": _FOREIGN_TOKEN}).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        listener.settimeout(_SERVER_LIFETIME_SECONDS)
        try:
            connection, _ = listener.accept()
        except (OSError, TimeoutError):
            return
        with connection:
            connection.settimeout(_SERVER_LIFETIME_SECONDS)
            try:
                connection.recv(_READ_SIZE)
                connection.sendall(reply)
            except OSError:
                return


def test_the_supervised_install_carries_the_guest_through_a_power_cycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The install reaches a running agent only because the guest is relaunched.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture used to configure the stand-in guest.
    """
    log = tmp_path / "boots.jsonl"
    monkeypatch.setenv(BOOT_LOG_VARIABLE, str(log))
    monkeypatch.setenv(ANSWER_ON_BOOT_VARIABLE, "2")
    monkeypatch.setenv(BOOT_SECONDS_VARIABLE, "2.0")
    command = _argv_with_free_channel(tmp_path)

    outcome = run_unattended_install(
        command,
        timeout_seconds=_SUPERVISION_BUDGET_SECONDS,
        restart_limit=_RESTART_LIMIT,
        poll_seconds=_POLL_SECONDS,
        shutdown_grace_seconds=_SHUTDOWN_GRACE_SECONDS,
    )

    boots = _recorded_boots(log)
    assert outcome.completed, f"the install never reached a running agent: {outcome.detail} across {len(boots)} boots"
    assert outcome.restarts == _EXPECTED_POWER_CYCLES, f"the guest power cycled once, but the outcome reports {outcome.restarts}"
    assert len(boots) == _EXPECTED_POWER_CYCLES + 1, f"the guest was launched {len(boots)} times rather than twice"
    assert _ONCE_ELEMENT in _argument_value(boots[0], _BOOT_ARGUMENT), (
        "the first boot did not boot the installation medium, so this run proves nothing about the second"
    )
    assert _ONCE_ELEMENT not in _argument_value(boots[1], _BOOT_ARGUMENT), (
        "the relaunched guest booted the installation medium again, which restarts the installation"
    )
    assert power_cycling_guest.shutdown_marker(log).is_file(), (
        "the finished guest was never asked to power itself off, so its disk is left mid-write"
    )


def test_the_supervisor_gives_up_rather_than_relaunching_forever(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A guest that never reaches an agent must end the run, not loop.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture used to configure the stand-in guest.
    """
    log = tmp_path / "boots.jsonl"
    monkeypatch.setenv(BOOT_LOG_VARIABLE, str(log))
    monkeypatch.setenv(ANSWER_ON_BOOT_VARIABLE, "0")
    monkeypatch.setenv(BOOT_SECONDS_VARIABLE, "0.5")
    command = _argv_with_free_channel(tmp_path)

    outcome = run_unattended_install(
        command,
        timeout_seconds=_SUPERVISION_BUDGET_SECONDS,
        restart_limit=_RESTART_LIMIT,
        poll_seconds=_POLL_SECONDS,
        shutdown_grace_seconds=_SHUTDOWN_GRACE_SECONDS,
    )

    assert not outcome.completed, "a guest whose agent never answered was reported as an installed system"
    assert outcome.restarts == _RESTART_LIMIT + 1, (
        f"the run stopped after {outcome.restarts} power cycles rather than one past the {_RESTART_LIMIT} allowed"
    )
    assert len(_recorded_boots(log)) == _EXPECTED_GIVE_UP_BOOTS, (
        f"the guest was launched {len(_recorded_boots(log))} times for a limit of {_RESTART_LIMIT}"
    )
    assert str(outcome.restarts) in outcome.detail, f"the verdict does not say what happened: {outcome.detail!r}"


def test_an_argv_without_an_agent_channel_is_refused(tmp_path: Path) -> None:
    """Supervising a guest whose readiness cannot be observed is not possible.

    Args:
        tmp_path: Per-test temporary directory.
    """
    command = _install_argv(tmp_path, _CANDIDATE_AGENT_PORTS.start)
    without_channel = tuple(
        argument for index, argument in enumerate(command) if argument != "-chardev" and (index == 0 or command[index - 1] != "-chardev")
    )

    assert agent_channel_port(command) > 0, "the install argv carries no agent channel to remove"
    with pytest.raises(ProvisioningError, match="no guest agent channel"):
        agent_channel_port(without_channel)
