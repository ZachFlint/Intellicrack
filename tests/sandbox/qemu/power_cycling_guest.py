# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""A stand-in for QEMU that power cycles before its guest agent ever answers.

Windows Setup power cycles the guest between its phases, and QEMU exits when
it does. That was measured against real Windows 11 26100 installs: every run
ended ``rc=0`` partway through, on two different command lines, and relaunching
the guest off its system disk carried the installation to a booted system
whose agent answered.

Reproducing that against a real hypervisor takes a Windows guest, an hour of
wall clock and an accelerator no test host is guaranteed, so this reproduces
the host-visible shape of it instead: a process that binds the agent channel
its own argv names, refuses to answer on its first boot, exits of its own
accord, and answers once it has been relaunched. Everything the supervisor
does around it - deriving the resume argv, deriving the channel port, spawning
and respawning, framing the agent handshake, powering the guest off at the end
- is the real production code running for real.

The run is configured through the environment rather than the argument vector
so the vector can be the one :func:`build_install_command` really emits.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Final, cast


BOOT_LOG_VARIABLE: Final[str] = "ICFAKEQEMU_BOOT_LOG"
ANSWER_ON_BOOT_VARIABLE: Final[str] = "ICFAKEQEMU_ANSWER_ON_BOOT"
BOOT_SECONDS_VARIABLE: Final[str] = "ICFAKEQEMU_BOOT_SECONDS"

_DEFAULT_ANSWER_ON_BOOT: Final[str] = "2"
_DEFAULT_BOOT_SECONDS: Final[str] = "3.0"
_NEVER_ANSWER: Final[int] = 0

_CHARDEV_ARGUMENT: Final[str] = "-chardev"
_CHARDEV_PORT_PREFIX: Final[str] = "port="
_SYNC_DELIMITER: Final[bytes] = b"\xff"
_READ_SIZE: Final[int] = 4096
_ACCEPT_TIMEOUT_SECONDS: Final[float] = 0.25
_CONNECTION_TIMEOUT_SECONDS: Final[float] = 2.0
_LISTEN_BACKLOG: Final[int] = 4
_USAGE_EXIT_CODE: Final[int] = 2


def channel_port(argv: list[str]) -> int:
    """Return the agent channel port named by a QEMU argument vector.

    Args:
        argv: Argument vector, excluding the executable.

    Returns:
        int: Port of the ``-chardev`` socket, or 0 when there is none.
    """
    for index, argument in enumerate(argv[:-1]):
        if argument != _CHARDEV_ARGUMENT:
            continue
        for element in argv[index + 1].split(","):
            if element.startswith(_CHARDEV_PORT_PREFIX):
                return int(element[len(_CHARDEV_PORT_PREFIX) :])
    return 0


def record_boot(log: Path, argv: list[str]) -> int:
    """Append this boot's argument vector to the log and number it.

    Args:
        log: File the boots are recorded in, one JSON array per line.
        argv: Argument vector, excluding the executable.

    Returns:
        int: One-based index of this boot.
    """
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(argv) + "\n")
    return sum(1 for line in log.read_text(encoding="utf-8").splitlines() if line.strip())


def _decode_request(payload: bytes) -> dict[str, object] | None:
    """Decode one delimited guest agent request.

    Args:
        payload: Raw bytes read from the channel.

    Returns:
        dict[str, object] | None: The request, or None if it is not one.
    """
    for line in payload.split(b"\n"):
        text = line.strip(_SYNC_DELIMITER).strip()
        if not text:
            continue
        try:
            decoded: object = json.loads(text)
        except ValueError:
            continue
        if isinstance(decoded, dict):
            return cast("dict[str, object]", decoded)
    return None


def _sync_reply(request: dict[str, object]) -> bytes | None:
    """Build the reply to a synchronisation request.

    Args:
        request: Decoded guest agent request.

    Returns:
        bytes | None: Delimited reply echoing the identifier, or None when the
        request is not a synchronisation.
    """
    if request.get("execute") != "guest-sync-delimited":
        return None
    arguments = request.get("arguments")
    if not isinstance(arguments, dict):
        return None
    token = cast("dict[str, object]", arguments).get("id")
    if not isinstance(token, int):
        return None
    return _SYNC_DELIMITER + json.dumps({"return": token}).encode("utf-8") + b"\n"


def shutdown_marker(log: Path) -> Path:
    """Return the file that records the guest being asked to power off.

    Args:
        log: Boot log path.

    Returns:
        Path: Sibling file written when ``guest-shutdown`` arrives.
    """
    return log.with_suffix(".shutdown")


def serve(port: int, *, answer: bool, lifetime: float | None, marker: Path | None = None) -> int:
    """Bind the agent channel and serve it the way this boot is meant to.

    Args:
        port: TCP port to bind on loopback.
        answer: Whether a guest agent answers on this boot. A boot that does
            not answer still accepts connections, exactly as QEMU does before
            its guest has booted.
        lifetime: Seconds before this boot powers itself off, or None to run
            until the guest is asked to shut down.
        marker: File to write when the guest is asked to shut down, or None
            to record nothing.

    Returns:
        int: Process exit code.
    """
    deadline = None if lifetime is None else time.monotonic() + lifetime
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(_LISTEN_BACKLOG)
        listener.settimeout(_ACCEPT_TIMEOUT_SECONDS)
        while deadline is None or time.monotonic() < deadline:
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return 1
            with connection:
                connection.settimeout(_CONNECTION_TIMEOUT_SECONDS)
                try:
                    request = _decode_request(connection.recv(_READ_SIZE))
                except OSError:
                    continue
                if request is None:
                    continue
                if request.get("execute") == "guest-shutdown":
                    if marker is not None:
                        marker.write_text("powerdown\n", encoding="utf-8")
                    return 0
                reply = _sync_reply(request) if answer else None
                if reply is not None:
                    try:
                        connection.sendall(reply)
                    except OSError:
                        continue
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run one boot of the stand-in guest.

    Args:
        argv: Argument vector excluding the executable, or None to read
            ``sys.argv``.

    Returns:
        int: Process exit code; 2 when the boot log is not configured.
    """
    arguments = sys.argv[1:] if argv is None else argv
    log = os.environ.get(BOOT_LOG_VARIABLE)
    if not log:
        sys.stderr.write(f"{BOOT_LOG_VARIABLE} is not set\n")
        return _USAGE_EXIT_CODE

    boot_log = Path(log)
    boot = record_boot(boot_log, arguments)
    answer_on_boot = int(os.environ.get(ANSWER_ON_BOOT_VARIABLE, _DEFAULT_ANSWER_ON_BOOT))
    boot_seconds = float(os.environ.get(BOOT_SECONDS_VARIABLE, _DEFAULT_BOOT_SECONDS))
    answers = answer_on_boot != _NEVER_ANSWER and boot >= answer_on_boot
    return serve(
        channel_port(arguments),
        answer=answers,
        lifetime=None if answers else boot_seconds,
        marker=shutdown_marker(boot_log),
    )


if __name__ == "__main__":
    sys.exit(main())
