# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The folders an MCP server is told it may work in: the ``roots`` a client offers.

A server that asks ``roots/list`` is told which directories the operator is working in. Intellicrack answers from the active session and
from the server's own configuration, in this order:

* **Target.** The directory holding the session's active binary.
* **Binaries.** The directories of the session's other loaded binaries.
* **Session folders.** Folders the operator added to the session.
* **Server folders.** Folders configured for that one server only.
* **Sandbox folders.** For a sandboxed server, every ``allowWrite`` directory. The sandbox lets the server write there and nowhere else,
  so it is always told about them, and they cannot be excluded; every other root of a sandboxed server is one it may read but not write.

A server's configuration can switch roots off, which also withdraws the ``roots`` capability, leave out the session's roots, or exclude
particular session roots. Every root is sent as a ``file://`` URI: a Windows drive path becomes ``file:///C:/...`` and a UNC path
``file://host/share/...``, with every other character of every segment percent-encoded as UTF-8.

The session's roots change as binaries are loaded, sessions are switched and folders are added. :class:`McpRootSet` holds the current
set and tells its listeners what it was before and after, so a caller can announce ``notifications/roots/list_changed`` to exactly the
2025-11-25 servers whose own roots moved. A 2026-07-28 server asks for roots with the request that needs them, so it always sees the
current set without being told.
"""

from __future__ import annotations

import asyncio
import enum
import ntpath
import os
import posixpath
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final
from urllib.parse import quote

from mcp_types import ListRootsResult, Root

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from mcp.client.session import ClientRequestContext, ListRootsFnT

    from intellicrack.mcp.config import McpServerConfig


_logger = get_logger(__name__)

_WINDOWS: Final[bool] = os.name == "nt"


class RootSource(enum.StrEnum):
    """Where a root came from.

    Attributes:
        TARGET: The directory of the session's active binary.
        BINARY: The directory of another binary loaded in the session.
        SESSION: A folder the operator added to the session.
        SERVER: A folder configured for one server.
        SANDBOX: A sandboxed server's ``allowWrite`` directory.
    """

    TARGET = "target"
    BINARY = "binary"
    SESSION = "session"
    SERVER = "server"
    SANDBOX = "sandbox"


_SOURCE_LABELS: Final[dict[RootSource, str]] = {
    RootSource.TARGET: "Target binary folder",
    RootSource.BINARY: "Session binary folder",
    RootSource.SESSION: "Session folder",
    RootSource.SERVER: "Server folder",
    RootSource.SANDBOX: "Sandbox writable folder",
}


def _is_windows_path(path: str, *, windows: bool) -> bool:
    """Decide which path syntax a path is written in.

    Args:
        path: The path.
        windows: Whether the host is Windows.

    Returns:
        bool: ``True`` for Windows syntax.
    """
    return windows or bool(ntpath.splitdrive(path)[0])


def normalize_root_path(path: str, *, windows: bool = _WINDOWS) -> str:
    """Normalise a root's path so the same folder is always written the same way.

    Args:
        path: An absolute path.
        windows: Whether the host is Windows.

    Returns:
        str: The normalised path, without a trailing separator.

    Raises:
        ValueError: If the path is not absolute.
    """
    if _is_windows_path(path, windows=windows):
        drive, rest = ntpath.splitdrive(path)
        if not drive or not rest.startswith(("\\", "/")):
            message = f"root {path!r} is not an absolute path"
            raise ValueError(message)
        normalized = ntpath.normpath(path)
        return normalized if normalized.endswith(":\\") else normalized.rstrip("\\")
    if not posixpath.isabs(path):
        message = f"root {path!r} is not an absolute path"
        raise ValueError(message)
    normalized = posixpath.normpath(path)
    return "/" if normalized == "/" else normalized.rstrip("/")


def root_key(path: str, *, windows: bool = _WINDOWS) -> str:
    """Build the key two roots are compared by, so one folder is never offered twice.

    Args:
        path: A normalised root path.
        windows: Whether the host is Windows.

    Returns:
        str: The key; case-insensitive for a Windows path.
    """
    return ntpath.normcase(path) if _is_windows_path(path, windows=windows) else path


def root_uri(path: str, *, windows: bool = _WINDOWS) -> str:
    """Encode an absolute path as the ``file://`` URI a root is sent as.

    Args:
        path: An absolute path.
        windows: Whether the host is Windows.

    Returns:
        str: ``file:///C:/...`` for a drive path, its letter upper-cased, ``file://host/share/...``
        for a UNC path, ``file:///...`` for a POSIX path, with every segment
        percent-encoded as UTF-8.
    """
    normalized = normalize_root_path(path, windows=windows)
    if not _is_windows_path(normalized, windows=windows):
        segments = [quote(segment, safe="") for segment in normalized.split("/")[1:]]
        return "file:///" + "/".join(segments)
    drive, rest = ntpath.splitdrive(normalized)
    segments = [quote(segment, safe="") for segment in rest.replace("/", "\\").split("\\") if segment]
    if drive.startswith(("\\\\", "//")):
        host, _, share = drive.lstrip("\\/").replace("/", "\\").partition("\\")
        authority = quote(host, safe="")
        return f"file://{authority}/" + "/".join([quote(share, safe=""), *segments])
    return f"file:///{drive.upper()}/" + "/".join(segments)


@dataclass(frozen=True, slots=True)
class McpRoot:
    """One folder a server is told it may work in.

    Attributes:
        path: The folder's absolute, normalised path.
        source: Where the root came from.
        writable: For a sandboxed server, whether the sandbox lets it write
            here; ``None`` for a server that is not sandboxed.
    """

    path: str
    source: RootSource
    writable: bool | None = None

    @property
    def uri(self) -> str:
        """The ``file://`` URI the root is sent as.

        Returns:
            str: The URI.
        """
        return root_uri(self.path)

    @property
    def name(self) -> str:
        """The human-readable name sent with the root.

        Returns:
            str: What kind of root this is and the folder's own name.
        """
        leaf = ntpath.basename(self.path) if _is_windows_path(self.path, windows=_WINDOWS) else posixpath.basename(self.path)
        return f"{_SOURCE_LABELS[self.source]}: {leaf or self.path}"

    def to_protocol(self) -> Root:
        """Build the protocol's ``Root``.

        Returns:
            Root: The root as the server receives it.
        """
        return Root.model_validate({"uri": self.uri, "name": self.name})


def session_roots(*, target: str | None, binaries: Iterable[str], folders: Iterable[str]) -> tuple[McpRoot, ...]:
    """Collect a session's roots.

    Args:
        target: The active binary's path, or ``None``.
        binaries: Every loaded binary's path, the active one included.
        folders: Folders the operator added to the session.

    Returns:
        tuple[McpRoot, ...]: The target's folder, then the other binaries'
        folders, then the operator's folders, each folder once. A path that
        is not absolute is logged and left out.
    """
    candidates: list[tuple[str, RootSource]] = []
    if target is not None:
        candidates.append((_parent(target), RootSource.TARGET))
    candidates.extend((_parent(binary), RootSource.BINARY) for binary in binaries)
    candidates.extend((folder, RootSource.SESSION) for folder in folders)
    return _unique(candidates)


def _parent(path: str) -> str:
    """Name the folder a binary lives in.

    Args:
        path: The binary's path.

    Returns:
        str: Its folder.
    """
    if _is_windows_path(path, windows=_WINDOWS):
        return ntpath.dirname(ntpath.normpath(path))
    return posixpath.dirname(posixpath.normpath(path))


def _unique(candidates: Iterable[tuple[str, RootSource]], *, writable: Sequence[str] | None = None) -> tuple[McpRoot, ...]:
    """Normalise candidate roots and keep the first of each folder.

    Args:
        candidates: Paths and where each came from, in priority order.
        writable: For a sandboxed server, the folders it may write in.

    Returns:
        tuple[McpRoot, ...]: The roots.
    """
    writable_keys = None if writable is None else {root_key(normalize_root_path(entry)) for entry in writable}
    seen: set[str] = set()
    roots: list[McpRoot] = []
    for raw, source in candidates:
        try:
            path = normalize_root_path(raw)
        except ValueError as exc:
            _logger.warning("mcp_root_skipped", path=raw, reason=str(exc))
            continue
        key = root_key(path)
        if key in seen:
            continue
        seen.add(key)
        roots.append(McpRoot(path=path, source=source, writable=None if writable_keys is None else key in writable_keys))
    return tuple(roots)


def server_roots(config: McpServerConfig, session: Sequence[McpRoot]) -> tuple[McpRoot, ...]:
    """Work out the roots one server is offered.

    Args:
        config: The server's configuration.
        session: The session's roots.

    Returns:
        tuple[McpRoot, ...]: Nothing when the server's roots are off;
        otherwise the session's roots it is not excluded from (unless it
        leaves the session out), its own folders, and, when it is sandboxed,
        its ``allowWrite`` directories, each folder once.
    """
    spec = config.roots
    if not spec.enabled:
        return ()
    sandbox = config.sandbox
    candidates: list[tuple[str, RootSource]] = []
    if spec.include_session:
        excluded = {root_key(normalize_root_path(entry)) for entry in spec.exclude}
        candidates.extend((root.path, root.source) for root in session if root_key(root.path) not in excluded)
    candidates.extend((folder, RootSource.SERVER) for folder in spec.folders)
    if not sandbox.enabled:
        return _unique(candidates)
    candidates.extend((entry, RootSource.SANDBOX) for entry in sandbox.allow_write)
    return _unique(candidates, writable=sandbox.allow_write)


type RootsListener = Callable[[tuple[McpRoot, ...], tuple[McpRoot, ...]], None]
"""Told the session's roots before and after they changed."""


@dataclass(frozen=True, slots=True)
class _RootsChange:
    """A change to the session's roots, and the listeners to tell.

    Attributes:
        before: The roots before.
        after: The roots after.
        listeners: The listeners registered when it happened.
    """

    before: tuple[McpRoot, ...]
    after: tuple[McpRoot, ...]
    listeners: tuple[RootsListener, ...]


class McpRootSet:
    """The active session's roots, shared by every connection.

    Read from the event loop by the roots callbacks and written from the GUI
    thread as the session changes, so the current set is swapped under a lock.
    """

    def __init__(self) -> None:
        """Start with no session roots."""
        self._lock = threading.Lock()
        self._session: tuple[McpRoot, ...] = ()
        self._folders: tuple[str, ...] = ()
        self._target: str | None = None
        self._binaries: tuple[str, ...] = ()
        self._listeners: list[RootsListener] = []
        self._known: dict[str, tuple[McpRoot, ...]] = {}

    @property
    def session(self) -> tuple[McpRoot, ...]:
        """The session's current roots.

        Returns:
            tuple[McpRoot, ...]: The roots.
        """
        with self._lock:
            return self._session

    @property
    def folders(self) -> tuple[str, ...]:
        """The folders the operator added to the session.

        Returns:
            tuple[str, ...]: The folders, as entered.
        """
        with self._lock:
            return self._folders

    def set_session(self, *, target: str | None, binaries: Sequence[str], folders: Sequence[str]) -> bool:
        """Replace the session's roots.

        Args:
            target: The active binary's path, or ``None``.
            binaries: Every loaded binary's path.
            folders: Folders the operator added to the session.

        Returns:
            bool: Whether the roots changed; listeners are told when they did.
        """
        with self._lock:
            self._target = target
            self._binaries = tuple(binaries)
            self._folders = tuple(folders)
            change = self._swap()
        return self._announce(change)

    def set_folders(self, folders: Sequence[str]) -> bool:
        """Replace only the folders the operator added, keeping the binaries.

        Args:
            folders: The folders.

        Returns:
            bool: Whether the roots changed; listeners are told when they did.
        """
        with self._lock:
            self._folders = tuple(folders)
            change = self._swap()
        return self._announce(change)

    def _swap(self) -> _RootsChange | None:
        """Recompute the session's roots from its binaries and folders.

        The caller holds ``self._lock``.

        Returns:
            _RootsChange | None: The change and who to tell about it, or
            ``None`` when the roots are unchanged.
        """
        before = self._session
        after = session_roots(target=self._target, binaries=self._binaries, folders=self._folders)
        if after == before:
            return None
        self._session = after
        return _RootsChange(before=before, after=after, listeners=tuple(self._listeners))

    @staticmethod
    def _announce(change: _RootsChange | None) -> bool:
        """Tell the listeners about a change, outside the lock.

        Args:
            change: The change, or ``None``.

        Returns:
            bool: Whether there was a change.
        """
        if change is None:
            return False
        _logger.info("mcp_session_roots_changed", count=len(change.after))
        for listener in change.listeners:
            listener(change.before, change.after)
        return True

    def preview(self, folders: Sequence[str]) -> tuple[McpRoot, ...]:
        """Work out what the session's roots would be with other operator folders.

        Args:
            folders: The folders the operator is considering.

        Returns:
            tuple[McpRoot, ...]: The session's roots with those folders.
        """
        with self._lock:
            return session_roots(target=self._target, binaries=self._binaries, folders=folders)

    def roots_for(self, config: McpServerConfig) -> tuple[McpRoot, ...]:
        """Work out the roots one server is offered now.

        Args:
            config: The server's configuration.

        Returns:
            tuple[McpRoot, ...]: The roots.
        """
        return server_roots(config, self.session)

    def add_listener(self, listener: RootsListener) -> None:
        """Be told whenever the session's roots change.

        Args:
            listener: Called with the roots before and after, on the thread
                that changed them.
        """
        with self._lock:
            self._listeners.append(listener)

    def remove_listener(self, listener: RootsListener) -> None:
        """Stop telling a listener about changes.

        Args:
            listener: A listener added earlier.
        """
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def stale(self, configs: Iterable[McpServerConfig]) -> list[str]:
        """Name the servers whose roots have moved since they last learned them.

        A server learns its roots by asking for them, or by being told they
        changed; each server named here is taken to have been told, so the
        same change is announced once.

        Args:
            configs: The servers' current configurations.

        Returns:
            list[str]: The ids of servers that asked for their roots before
            and would now get a different answer.
        """
        session = self.session
        stale: list[str] = []
        with self._lock:
            for config in configs:
                known = self._known.get(config.server_id)
                current = server_roots(config, session)
                if known is not None and known != current:
                    self._known[config.server_id] = current
                    stale.append(config.server_id)
        return stale

    def listed(self, config: McpServerConfig) -> tuple[McpRoot, ...]:
        """Answer a server that asks for its roots, remembering what it was told.

        Args:
            config: The server's configuration.

        Returns:
            tuple[McpRoot, ...]: The server's roots now.
        """
        roots = self.roots_for(config)
        with self._lock:
            self._known[config.server_id] = roots
        _logger.debug("mcp_roots_listed", server_id=config.server_id, count=len(roots))
        return roots

    def callback_for(self, config: McpServerConfig, lookup: Callable[[str], McpServerConfig | None]) -> ListRootsFnT:
        """Build the ``roots/list`` handler for one server.

        Args:
            config: The server's configuration when its connection was built.
            lookup: Finds the server's configuration as last saved, so a root
                edited since the connection opened is answered without a
                restart.

        Returns:
            ListRootsFnT: The handler, which answers with the server's roots
            as they are when it is asked.
        """
        server_id = config.server_id

        async def _list_roots(context: ClientRequestContext) -> ListRootsResult:
            """Answer ``roots/list``.

            Args:
                context: The SDK's request context, unused.

            Returns:
                ListRootsResult: The server's current roots.
            """
            del context
            await asyncio.sleep(0)
            roots = self.listed(lookup(server_id) or config)
            return ListRootsResult(roots=[root.to_protocol() for root in roots])

        return _list_roots
