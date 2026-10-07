# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Third-pass coverage for ``intellicrack.bridges.ghidra``.

A file whose own access-control list denies attribute reads, inside a directory whose
list denies listing, makes ``Path.exists`` raise ``PermissionError`` (measured with real
``icacls`` deny entries). That is the only way the two path validators see an ``OSError``
from the existence check, so those tests set the entries on real files under
``tmp_path`` and always remove them again.

A second Python socket built over the handle of a connected loopback socket makes the
RPC-client close raise ``OSError`` once the first socket has closed the shared handle
(measured: WinError 10038 on the second ``close``).
"""

from __future__ import annotations

import importlib
import os
import socket
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest
from structlog.testing import capture_logs

from intellicrack.bridges import ghidra as ghidra_module
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


pytestmark = pytest.mark.spawns_process

_EVERYONE_SID: Final[str] = "*S-1-1-0"
_ICACLS_TIMEOUT_SECONDS: Final[float] = 30.0
_WSAENOTSOCK: Final[int] = 10038
_UNUSED_RPC_PORT: Final[int] = 9


def _module_fn(name: str) -> Callable[[str], Path]:
    """Resolve a module-level path validator of the Ghidra bridge by name.

    Args:
        name: Attribute name inside ``intellicrack.bridges.ghidra``.

    Returns:
        Callable[[str], Path]: The validator, typed as a callable taking a path string.
    """
    return cast("Callable[[str], Path]", getattr(ghidra_module, name))


def _icacls(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the Windows ``icacls`` tool with the given arguments.

    Args:
        *args: Arguments passed to ``icacls``.

    Returns:
        subprocess.CompletedProcess[str]: The finished process with captured text output.
    """
    executable = Path(os.environ["SYSTEMROOT"]) / "System32" / "icacls.exe"
    return subprocess.run(
        [str(executable), *args],
        capture_output=True,
        text=True,
        timeout=_ICACLS_TIMEOUT_SECONDS,
        check=False,
    )


@pytest.fixture
def stat_denied_file(tmp_path: Path) -> Iterator[Path]:
    """Provide a real file whose metadata cannot be read by anyone.

    The file denies attribute reads to Everyone and its parent directory denies
    listing to Everyone, so neither the direct attribute query nor the directory
    scan fallback of ``os.stat`` is permitted. Both entries are removed on teardown,
    the directory first because the file cannot be reached while it is locked.

    Args:
        tmp_path: Pytest temporary directory that holds the locked folder.

    Yields:
        Path: The locked file.
    """
    folder = tmp_path / "locked"
    folder.mkdir()
    target = folder / "header.h"
    target.write_text("int value;\n", encoding="utf-8")
    try:
        for item, rights in ((target, "RA"), (folder, "RD")):
            done = _icacls(str(item), "/deny", f"{_EVERYONE_SID}:({rights})")
            assert done.returncode == 0, done.stdout + done.stderr
        yield target
    finally:
        _icacls(str(folder), "/reset")
        _icacls(str(target), "/reset")


@pytest.mark.parametrize(
    ("resolver", "prefix"),
    [
        ("_resolve_debug_info_path", "Debug info file path invalid: "),
        ("_resolve_c_header_path", "C header file path invalid: "),
    ],
)
def test_path_validator_reports_a_denied_stat_as_an_invalid_path(
    stat_denied_file: Path,
    resolver: str,
    prefix: str,
) -> None:
    """An ``OSError`` from the existence check becomes a ``ToolError`` that names the path.

    Args:
        stat_denied_file: Real file whose metadata cannot be read.
        resolver: Name of the validator under test.
        prefix: Documented start of the invalid-path message for that validator.
    """
    with pytest.raises(PermissionError) as stat_error:
        _ = stat_denied_file.stat()

    with pytest.raises(ToolError) as caught:
        _ = _module_fn(resolver)(str(stat_denied_file))

    cause = caught.value.__cause__
    assert isinstance(cause, PermissionError)
    assert str(cause) == str(stat_error.value)
    assert str(caught.value) == f"{prefix}{stat_denied_file}: {stat_error.value}"


def _method(obj: object, name: str) -> Callable[..., object]:
    """Resolve a (possibly private) static method by name.

    Args:
        obj: Class that owns the attribute.
        name: Attribute name to look up.

    Returns:
        Callable[..., object]: The callable.
    """
    return cast("Callable[..., object]", getattr(obj, name))


def _rpc_client() -> object:
    """Build a real, lazy ``ghidra_bridge`` RPC client that never connects.

    Returns:
        object: The ``ghidra_bridge.GhidraBridge`` client instance.
    """
    module = importlib.import_module("ghidra_bridge")
    factory = cast("Callable[..., object]", getattr(module, "GhidraBridge"))
    return factory(namespace=None, connect_to_host="127.0.0.1", connect_to_port=_UNUSED_RPC_PORT, response_timeout=5)


@pytest.fixture
def loopback_client() -> Iterator[Callable[[], socket.socket]]:
    """Provide a factory for connected loopback client sockets.

    Every socket the factory opens, on both ends of each connection, is closed on teardown.

    Yields:
        Callable[[], socket.socket]: Factory returning the client end of a new connection.
    """
    opened: list[socket.socket] = []

    def make() -> socket.socket:
        """Open a listening socket, connect to it and accept the connection.

        Returns:
            socket.socket: The connected client end.
        """
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        opened.append(listener)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client = socket.create_connection(listener.getsockname(), timeout=5.0)
        opened.append(client)
        client.settimeout(None)
        peer, _ = listener.accept()
        opened.append(peer)
        return client

    try:
        yield make
    finally:
        for sock in reversed(opened):
            sock.close()


def _orphaned_socket(make_client: Callable[[], socket.socket]) -> socket.socket:
    """Build a connected socket whose handle another socket object has already closed.

    A second Python socket is constructed over the handle of a connected client, then
    the client closes that shared handle, leaving the second object holding a dead handle.

    Args:
        make_client: Factory returning the client end of a new loopback connection.

    Returns:
        socket.socket: The socket object whose handle is already closed.
    """
    client = make_client()
    twin = socket.socket(fileno=client.fileno())
    client.close()
    return twin


def test_close_bridge_client_logs_a_socket_whose_handle_is_already_closed(
    loopback_client: Callable[[], socket.socket],
) -> None:
    """A socket that fails to close with ``OSError`` is logged as a warning and never raised.

    Args:
        loopback_client: Factory for connected loopback client sockets.
    """
    with pytest.raises(OSError, match=rf"^\[WinError {_WSAENOTSOCK}\]") as direct:
        _orphaned_socket(loopback_client).close()
    assert direct.value.errno == _WSAENOTSOCK

    orphan = _orphaned_socket(loopback_client)
    rpc = _rpc_client()
    setattr(getattr(rpc, "client"), "sock", orphan)

    with capture_logs() as events:
        result = _method(GhidraBridge, "_close_bridge_client")(rpc)

    assert result is None
    assert [event["event"] for event in events] == ["ghidra_bridge_socket_close_failed"]
    assert events[0]["log_level"] == "warning"
    assert events[0]["exc_info"] is True
    assert orphan.fileno() == -1
