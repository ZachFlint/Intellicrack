# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Starting a session: bind a port, mint a token, open a window, and watch it.

The pieces are assembled in one order and there is only one of each. The port is
bound as zero and read back, so two sessions never collide and no configured port
can be squatted. The token is minted per session and never written to disk, so it
dies with the process.

How the session ends depends on how it was shown. The embedded window owns the
main thread and returns when it is closed, which is a definite signal, so the
server runs on a worker thread and is stopped the moment that call returns. The
external browser is opened through ``ShellExecuteW``, which returns no process
handle, so closing that window is invisible to this process; there the server
runs on the main thread and silence is the exit signal instead -- the page beats,
and when the beats stop the server stops. That watchdog also covers the mode that
only prints the address, where there is no child process at all.
"""

from __future__ import annotations

import argparse
import secrets
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

from hexbench.api import Application
from hexbench.dispatch import Invocation, invoke, operation_for
from hexbench.jobs import JobQueue
from hexbench.registry import Registry
from hexbench.server import bound_url, build_server
from hexbench.shell import announce, open_shell
from hexbench.window import run_window


if TYPE_CHECKING:
    from collections.abc import Sequence

    from hexbench.codec import JsonValue
    from hexbench.server import BenchHTTPServer
    from hexbench.window import WebviewWindow


__all__ = ["SHELL_BROWSER", "SHELL_CHOICES", "SHELL_NONE", "SHELL_WINDOW", "ServerStop", "build_argument_parser", "main", "resolve_shell"]

_DEFAULT_HOST: Final = "127.0.0.1"
_DEFAULT_PORT: Final = 0
_DEFAULT_IDLE_TIMEOUT: Final = 30.0
_TOKEN_BYTES: Final = 32
_WATCH_INTERVAL: Final = 1.0
_POLL_INTERVAL: Final = 0.25
_STATIC_DIRECTORY: Final = "static"
_OPEN_OPERATION: Final = "open"
_PATH_ARGUMENT: Final = "path"
_DISABLED: Final = 0.0
_SHUTDOWN_TIMEOUT: Final = 5.0

SHELL_WINDOW: Final = "window"
SHELL_BROWSER: Final = "browser"
SHELL_NONE: Final = "none"
SHELL_CHOICES: Final = (SHELL_WINDOW, SHELL_BROWSER, SHELL_NONE)

_STARTUP_FAILURES: Final[tuple[type[Exception], ...]] = (OSError, ValueError, RuntimeError, LookupError)


class ServerStop:
    """A shutdown callable that can be handed out before the server exists.

    In the embedded shell the window, not the server, is what holds the process
    open: the toolkit's event loop owns the main thread and only returns once
    the window goes away. Stopping the server alone would leave that window on
    screen with a dead backend behind it, so a session ended from the page
    closes the window too.
    """

    def __init__(self) -> None:
        """Create a stopper that is not yet attached to a server or window."""
        self._server: BenchHTTPServer | None = None
        self._window: WebviewWindow | None = None

    def attach(self, server: BenchHTTPServer) -> None:
        """Bind this stopper to the server it should stop.

        Args:
            server: The bound server.
        """
        self._server = server

    def attach_window(self, window: WebviewWindow) -> None:
        """Bind this stopper to the window it should close.

        Args:
            window: The embedded window this session is being shown in.
        """
        self._window = window

    def __call__(self) -> None:
        """Stop the attached server and close the attached window, if any."""
        server = self._server
        if server is not None:
            server.shutdown()
        window = self._window
        if window is not None:
            window.destroy()


def build_argument_parser() -> argparse.ArgumentParser:
    """Describe the command line.

    Returns:
        argparse.ArgumentParser: The parser for this entry point.
    """
    parser = argparse.ArgumentParser(prog="hexbench", description="A hex editor for the intellicrack_hexcore engine.")
    parser.add_argument("--host", default=_DEFAULT_HOST, help="interface to bind (default: %(default)s)")
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT, help="port to bind; 0 lets the system choose (default: %(default)s)")
    parser.add_argument(
        "--shell",
        choices=SHELL_CHOICES,
        default=None,
        help=f"how to show the editor: an embedded window, an external browser, or neither (default: {SHELL_WINDOW})",
    )
    parser.add_argument(
        "--browser",
        type=Path,
        default=None,
        help=f"browser executable to use instead of the detected one; implies --shell {SHELL_BROWSER}",
    )
    parser.add_argument("--open", dest="targets", type=Path, action="append", help="open a file at startup; repeatable")
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=_DEFAULT_IDLE_TIMEOUT,
        help="seconds of client silence before the server stops; 0 disables (default: %(default)s)",
    )
    return parser


def _open_documents(registry: Registry, targets: Sequence[Path]) -> None:
    """Open the files named on the command line.

    A file that cannot be opened is reported and skipped, so one bad path on the
    command line does not stop the session from starting.

    Args:
        registry: Registry to register the opened documents with.
        targets: Files to open.
    """
    if not targets:
        return
    operation = operation_for(_OPEN_OPERATION)
    for target in targets:
        arguments: dict[str, JsonValue] = {_PATH_ARGUMENT: str(target)}
        try:
            invoke(registry, Invocation(operation=operation, handle=None, arguments=arguments))
        except _STARTUP_FAILURES as exc:
            sys.stderr.write(f"hexbench: cannot open {target}: {exc}\n")


def _watch_for_silence(server: BenchHTTPServer, application: Application, timeout: float, stopping: threading.Event) -> None:
    """Stop the server once the client has been quiet for too long.

    Args:
        server: The running server.
        application: Routing table whose heartbeat is being watched.
        timeout: Seconds of silence that count as the client having gone.
        stopping: Set when the server is already on its way down.
    """
    while not stopping.wait(_WATCH_INTERVAL):
        if application.seconds_since_heartbeat() > timeout:
            server.record(f"no client activity for {timeout} seconds; stopping")
            server.shutdown()
            return


def _start_watchdog(server: BenchHTTPServer, application: Application, timeout: float) -> threading.Event:
    """Start the thread that ends the session once the client falls silent.

    Args:
        server: The bound server.
        application: Routing table whose heartbeat is being watched.
        timeout: Seconds of silence that count as the client having gone; any
            value at or below zero disables the watchdog entirely.

    Returns:
        threading.Event: Set by the caller once the server is on its way down,
        which is what stops the watchdog thread.
    """
    stopping = threading.Event()
    if timeout > _DISABLED:
        thread = threading.Thread(
            target=_watch_for_silence,
            args=(server, application, timeout, stopping),
            name="hexbench-watchdog",
            daemon=True,
        )
        thread.start()
    return stopping


class _Session(NamedTuple):
    """Everything one session owns, assembled and wired together."""

    registry: Registry
    jobs: JobQueue
    application: Application
    server: BenchHTTPServer
    url: str
    stopper: ServerStop


def _build_session(host: str, port: int) -> _Session:
    """Assemble one session's parts and bind its port.

    The token is minted here and reaches the page only through the returned
    address, so it is never written anywhere that outlives the process.

    Args:
        host: Interface to bind.
        port: Port to bind, where zero lets the system choose one.

    Returns:
        _Session: The assembled session, with its server already bound.
    """
    registry = Registry()
    jobs = JobQueue()
    stopper = ServerStop()
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    application = Application(
        registry,
        jobs,
        static_root=Path(__file__).resolve().parent / _STATIC_DIRECTORY,
        token=token,
        shutdown=stopper,
    )
    server = build_server(application, host, port)
    stopper.attach(server)
    application.bind(server.bound_address[1])
    return _Session(registry, jobs, application, server, bound_url(server, token), stopper)


def resolve_shell(parser: argparse.ArgumentParser, requested: str | None, browser: Path | None) -> str:
    """Decide how the editor should be shown.

    Naming a browser executable is only meaningful when an external browser is
    the thing being opened, so it selects that mode on its own but is rejected
    rather than silently ignored if some other mode was also asked for.

    Args:
        parser: Parser to report a contradictory combination through.
        requested: The mode named on the command line, or ``None`` if it was left
            to the default.
        browser: Browser executable named on the command line, if any.

    Returns:
        str: One of the members of :data:`SHELL_CHOICES`.
    """
    if browser is not None and requested is not None and requested != SHELL_BROWSER:
        parser.error(f"--browser names the executable for --shell {SHELL_BROWSER}, so it cannot be combined with --shell {requested}")
    if requested is not None:
        return requested
    return SHELL_BROWSER if browser is not None else SHELL_WINDOW


def _serve_until_window_closes(server: BenchHTTPServer, url: str, stopper: ServerStop) -> None:
    """Serve the session for as long as the embedded window is open.

    The window toolkit's event loop has to own the main thread, so the server is
    the part that moves aside. The join is bounded because a request already in
    flight when the window closed must not be able to hold the process open.

    Args:
        server: The bound server.
        url: Address to open in the window, including the session token.
        stopper: The session's stopper, handed the window once it exists so that
            ending the session from the page closes the window as well.
    """
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": _POLL_INTERVAL},
        name="hexbench-server",
        daemon=True,
    )
    thread.start()
    try:
        run_window(url, on_ready=stopper.attach_window)
    finally:
        server.shutdown()
        thread.join(_SHUTDOWN_TIMEOUT)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one hexbench session until its window closes.

    Args:
        argv: Command line arguments, or ``None`` to read them from the process.

    Returns:
        int: Process exit status; zero once the session has ended cleanly.
    """
    parser = build_argument_parser()
    arguments = parser.parse_args(argv)
    host: str = arguments.host
    port: int = arguments.port
    browser: Path | None = arguments.browser
    targets: list[Path] = arguments.targets or []
    idle_timeout: float = arguments.idle_timeout
    shell = resolve_shell(parser, arguments.shell, browser)
    embedded = shell == SHELL_WINDOW

    session = _build_session(host, port)
    _open_documents(session.registry, targets)

    if shell == SHELL_NONE:
        announce(session.url)
    elif shell == SHELL_BROWSER:
        open_shell(session.url, override=browser)

    stopping = _start_watchdog(session.server, session.application, _DISABLED if embedded else idle_timeout)
    try:
        if embedded:
            _serve_until_window_closes(session.server, session.url, session.stopper)
        else:
            session.server.serve_forever(poll_interval=_POLL_INTERVAL)
    except KeyboardInterrupt:
        sys.stderr.write("hexbench: interrupted\n")
    finally:
        stopping.set()
        session.server.server_close()
        session.jobs.shutdown()
        session.registry.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
