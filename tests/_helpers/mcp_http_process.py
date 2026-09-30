# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Run a real MCP server script as a loopback HTTP server for the length of a block.

A gate that needs a remote server -- Streamable HTTP or the legacy HTTP+SSE transport -- starts the script in a child process on a free
loopback port, waits until it accepts connections, and stops it afterwards, whatever the block did.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


_BOOT_TIMEOUT_S: Final[float] = 60.0
_POLL_S: Final[float] = 0.2
_STOP_TIMEOUT_S: Final[float] = 10.0


def free_port() -> int:
    """Reserve a loopback port a server can bind.

    Returns:
        int: A port that was free at the moment of asking.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def await_port(port: int, process: subprocess.Popen[bytes]) -> None:
    """Wait for a server process to accept connections.

    Args:
        port: The loopback port it binds.
        process: The process, watched so a crash fails fast.

    Raises:
        RuntimeError: If it exits or never accepts in time.
    """
    deadline = time.monotonic() + _BOOT_TIMEOUT_S
    while time.monotonic() < deadline:
        if process.poll() is not None:
            message = f"the server process exited with {process.returncode} before accepting"
            raise RuntimeError(message)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(_POLL_S)
    message = f"the server process never accepted on port {port}"
    raise RuntimeError(message)


@contextmanager
def running_server(script: Path, *args: str) -> Generator[int]:
    """Run a server script on a free loopback port until the block exits.

    The script receives ``--port <port>`` after ``args``.

    Args:
        script: The server script.
        *args: Arguments selecting its mode and transport.

    Yields:
        int: The port it listens on.
    """
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, str(script), *args, "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        await_port(port, process)
        yield port
    finally:
        process.terminate()
        try:
            _ = process.wait(timeout=_STOP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            process.kill()
            _ = process.wait(timeout=_STOP_TIMEOUT_S)


__all__ = ["await_port", "free_port", "running_server"]
