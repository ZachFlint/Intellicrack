# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Transport construction for Model Context Protocol connections.

Two shapes reach the SDK from here. A local server becomes a
:class:`~mcp.client.stdio.StdioServerParameters` whose argv is resolved
without a shell, and a remote server becomes a Streamable HTTP stream pair
built on an ``httpx2`` client that carries the configured headers, the
composed query string, and any OAuth handler.

The stdio path is the security-sensitive one. ``StdioServerParameters``
launches ``command`` with ``args`` directly, never through a shell, so a
metacharacter in the command is not interpreted -- but a command containing
one is still a sign the operator pasted a shell pipeline where a program name
belongs, and running its first word alone is not what they asked for. Those
commands are refused outright rather than silently truncated.
"""

from __future__ import annotations

import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx2
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from intellicrack.core.logging import get_logger
from intellicrack.mcp.errors import McpConfigError


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Mapping

    from intellicrack.mcp.config import HttpServerSpec, StdioServerSpec


_logger = get_logger(__name__)


SHELL_METACHARACTERS: Final[tuple[str, ...]] = ("&", "|", ";", "`", "$(", "${", ">", "<", "\n", "\r", "\0")
"""Sequences that make a command a shell fragment rather than a program name."""

_ENV_FILE_MAX_BYTES: Final[int] = 256 * 1024
"""Upper bound on an ``envFile`` so a mistargeted path cannot exhaust memory."""

_QUOTED_VALUE_MIN_CHARS: Final[int] = 2
"""Shortest value that can be a pair of matching quotes around content."""

_ERR_EMPTY_COMMAND = "the launch command is empty"

WEB_URL_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})
"""Schemes a URL from a server may be handed to the operator's browser."""


def is_web_url(url: str) -> bool:
    """Report whether a URL is safe to hand to the platform's URL handler.

    Args:
        url: The URL to test.

    Returns:
        bool: ``True`` for an ``http`` or ``https`` URL that names a host.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme.lower() in WEB_URL_SCHEMES and bool(parts.netloc)


def open_web_url(url: str) -> bool:
    """Open a URL in the operator's browser, refusing anything but the web.

    Neither of the URLs Intellicrack opens on a server's behalf -- an
    elicitation destination and an OAuth authorization page -- is written by
    the operator. :func:`webbrowser.open` falls back to the platform handler,
    which on Windows is ``ShellExecute``: it launches whatever the shell
    associates with the string, so a ``file://`` URL naming an executable, a
    UNC path, or a scheme some installed program registered would start a
    program rather than open a page. Restricting the scheme is what keeps a
    single click on a dialog from doing that.

    Args:
        url: The URL to open.

    Returns:
        bool: ``True`` when the URL was handed to the browser, ``False``
        when it was refused or no browser could be launched.
    """
    if not is_web_url(url):
        _logger.warning("mcp_url_open_refused", scheme=urlsplit(url).scheme[:32] if "//" in url else "")
        return False
    return webbrowser.open(url)


@runtime_checkable
class McpTransport(Protocol):
    """An async context manager yielding an MCP read/write stream pair.

    Both transports the client uses satisfy this shape, which is also what
    :class:`mcp.Client` accepts for its ``server`` argument, so a connection
    can be opened without the client caring which one it got.
    """

    async def __aenter__(self) -> tuple[Any, Any]:
        """Open the transport.

        Returns:
            tuple[Any, Any]: The read stream and the write stream.
        """
        ...

    async def __aexit__(self, *exc: object) -> None:
        """Close the transport.

        Args:
            *exc: Exception type, value and traceback, when the body raised.
        """
        ...


def find_shell_metacharacters(command: str) -> tuple[str, ...]:
    """List the shell metacharacters a command contains.

    Args:
        command: The configured launch command.

    Returns:
        tuple[str, ...]: Matching sequences from :data:`SHELL_METACHARACTERS`,
        in the order they are defined.
    """
    return tuple(token for token in SHELL_METACHARACTERS if token in command)


def load_env_file(path: Path) -> dict[str, str]:
    """Read a ``KEY=VALUE`` environment file.

    Blank lines and ``#`` comments are skipped. A value may be wrapped in
    matching single or double quotes, which are stripped; nothing else is
    interpreted, so a value is never expanded against the parent environment.

    Args:
        path: File to read.

    Returns:
        dict[str, str]: The parsed entries, later lines winning.

    Raises:
        McpConfigError: If the file is missing, too large, or unreadable.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        message = f"cannot read env file {path}: {exc}"
        raise McpConfigError(message) from exc
    if size > _ENV_FILE_MAX_BYTES:
        message = f"env file {path} is {size} bytes, above the {_ENV_FILE_MAX_BYTES} byte limit"
        raise McpConfigError(message)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        message = f"cannot read env file {path}: {exc}"
        raise McpConfigError(message) from exc

    entries: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator:
            continue
        key = name.strip().removeprefix("export ").strip()
        if not key:
            continue
        stripped = value.strip()
        if len(stripped) >= _QUOTED_VALUE_MIN_CHARS and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
            stripped = stripped[1:-1]
        entries[key] = stripped
    return entries


def build_stdio_parameters(spec: StdioServerSpec, env: Mapping[str, str]) -> StdioServerParameters:
    """Build launch parameters for a local server.

    Args:
        spec: The configured launch description.
        env: Fully resolved environment entries, with every
            ``${input:id}`` reference already expanded.

    Returns:
        StdioServerParameters: Parameters the SDK spawns without a shell.

    Raises:
        McpConfigError: If the command is empty, contains a shell
            metacharacter, an argument or environment value still carries an
            unresolved reference, any value embeds a NUL, or the working
            directory does not exist.
    """
    command = spec.command.strip()
    if not command:
        raise McpConfigError(_ERR_EMPTY_COMMAND)

    found = find_shell_metacharacters(command)
    if found:
        rendered = " ".join(repr(token) for token in found)
        message = (
            f"launch command {command!r} contains shell metacharacters ({rendered}). "
            f"Intellicrack resolves the command without a shell, so a shell fragment would not run as written; "
            f"give the program name in 'command' and each argument separately in 'args'."
        )
        raise McpConfigError(message)

    for index, argument in enumerate(spec.args):
        if "\0" in argument:
            message = f"argument {index} of {command!r} contains a NUL byte"
            raise McpConfigError(message)
        _reject_unresolved(argument, f"args[{index}]")

    for name, value in env.items():
        if "\0" in name or "\0" in value:
            message = f"environment entry {name!r} for {command!r} contains a NUL byte"
            raise McpConfigError(message)
        _reject_unresolved(value, f"env.{name}")

    cwd: str | None = None
    if spec.cwd is not None:
        directory = Path(spec.cwd)
        if not directory.is_dir():
            message = f"working directory {spec.cwd!r} for {command!r} does not exist"
            raise McpConfigError(message)
        cwd = str(directory)

    return StdioServerParameters(
        command=command,
        args=list(spec.args),
        env=dict(env),
        cwd=cwd,
        encoding="utf-8",
        encoding_error_handler="replace",
    )


def _reject_unresolved(value: str, field: str) -> None:
    """Refuse a value that still carries an unexpanded input reference.

    Args:
        value: The value about to reach a child process.
        field: Field name used in the error message.

    Raises:
        McpConfigError: If the value still contains ``${input:``.
    """
    if "${input:" in value:
        message = f"{field} still contains an unresolved ${{input:...}} reference; refusing to pass it to the server"
        raise McpConfigError(message)


def compose_endpoint_url(url: str, query: Mapping[str, str]) -> str:
    """Merge configured query parameters into an endpoint URL.

    Parameters already present in ``url`` are kept and the configured ones
    are appended, so a server whose URL carries a path-level parameter does
    not lose it.

    Args:
        url: The configured endpoint URL.
        query: Resolved query parameters to add.

    Returns:
        str: The endpoint URL with ``query`` composed onto it.
    """
    if not query:
        return url
    parts = urlsplit(url)
    merged: list[tuple[str, str]] = [*parse_qsl(parts.query, keep_blank_values=True), *query.items()]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(merged), parts.fragment))


@asynccontextmanager
async def open_http_transport(
    spec: HttpServerSpec,
    *,
    headers: Mapping[str, str],
    auth: httpx2.Auth | None,
    timeout_s: float,
) -> AsyncGenerator[tuple[Any, Any]]:
    """Open a Streamable HTTP transport for a remote server.

    The SDK's ``StreamableHTTPTransport`` takes only a URL: headers and
    authorization ride on the ``httpx2`` client handed to
    :func:`mcp.client.streamable_http.streamable_http_client`, which is what
    this builds. Redirects are followed by the SDK only within the endpoint's
    own origin.

    Args:
        spec: The configured endpoint description.
        headers: Fully resolved request headers.
        auth: An ``httpx2`` authentication handler, or ``None`` for an
            unauthenticated endpoint. ``OAuthClientProvider`` is one.
        timeout_s: Connect and write timeout in seconds. The read timeout is
            left long because a server may hold a response stream open.

    A header still carrying an unresolved reference propagates
    :class:`McpConfigError` from :func:`_reject_unresolved`.

    Yields:
        tuple[Any, Any]: The read stream and the write stream.
    """
    for name, value in headers.items():
        _reject_unresolved(value, f"headers.{name}")

    endpoint = compose_endpoint_url(spec.url, spec.query)
    timeout = httpx2.Timeout(timeout_s, read=_stream_read_timeout(timeout_s))
    client = _build_http_client(headers=headers, timeout=timeout, auth=auth)
    _logger.debug("mcp_http_transport_opening", endpoint=_redact_endpoint(endpoint), authenticated=auth is not None)
    async with client, streamable_http_client(endpoint, http_client=client) as streams:
        read_stream, write_stream = streams[0], streams[1]
        yield read_stream, write_stream


def _build_http_client(
    *,
    headers: Mapping[str, str],
    timeout: httpx2.Timeout,
    auth: httpx2.Auth | None,
) -> httpx2.AsyncClient:
    """Build the ``httpx2`` client a Streamable HTTP transport rides on.

    Settings match what the SDK's own transports use: the supplied timeouts,
    the configured headers, the supplied authentication handler, and redirect
    following left off, because the MCP transports follow same-origin
    redirects themselves and ignore the client's own setting.

    Args:
        headers: Fully resolved request headers.
        timeout: Connect, write and read timeouts.
        auth: An authentication handler, or ``None``.

    Returns:
        httpx2.AsyncClient: The client to hand to the transport.
    """
    return httpx2.AsyncClient(timeout=timeout, headers=dict(headers), auth=auth)


_STREAM_READ_TIMEOUT_FLOOR_S: Final[float] = 300.0
"""Read timeout floor, matching the SDK default for long-lived streams."""


def _stream_read_timeout(timeout_s: float) -> float:
    """Pick the read timeout for a server's HTTP client.

    Args:
        timeout_s: The server's configured per-call timeout.

    Returns:
        float: The larger of the configured timeout and the stream floor, so
        a short per-call timeout never severs the server's event stream.
    """
    return max(timeout_s, _STREAM_READ_TIMEOUT_FLOOR_S)


def _redact_endpoint(url: str) -> str:
    """Strip credentials and query values from a URL before logging it.

    Args:
        url: The endpoint URL.

    Returns:
        str: The scheme, host and path, with userinfo and every query value
        removed.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    keys = ",".join(name for name, _ in parse_qsl(parts.query, keep_blank_values=True))
    suffix = f"?{keys}" if keys else ""
    return f"{parts.scheme}://{host}{port}{parts.path}{suffix}"
