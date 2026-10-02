# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 32: servers are told which folders the operator works in, and told again when that changes.

The protocol gates connect Intellicrack's real connection to a real ``MCPServer`` whose tool asks for the client's roots, on 2026-07-28
over stdio (where the question rides ``InputRequiredResult``) and 2025-11-25 over SSE (a standalone ``roots/list``, and
``notifications/roots/list_changed`` when they move). The rest pin how roots are built: ``file://`` encoding of Windows paths, the
per-server settings, the sandbox's writable folders, which servers are told about a change, and the session keeping its folders.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

import pytest
from mcp_types import TextContent

from intellicrack.core.session import Session, SessionStore
from intellicrack.mcp.client_hooks import McpClientHooks
from intellicrack.mcp.config import McpRootsSpec, McpSandboxSpec, McpServerConfig
from intellicrack.mcp.errors import McpError
from intellicrack.mcp.roots import McpRoot, McpRootSet, RootSource, normalize_root_path, root_uri, server_roots, session_roots
from tests._helpers.mcp_features_server import CAPABILITIES_TOOL, ROOTS_CHANGES_TOOL, ROOTS_TOOL
from tests._helpers.mcp_features_support import Era, features_config, features_connection


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.mcp.connection import McpConnection


_ERAS: Final[list[Era]] = [Era.MODERN, Era.LEGACY]
_TIMEOUT_S: Final[float] = 90.0


@dataclass
class _Current:
    """The server's configuration as last saved, which the roots callback looks up.

    Attributes:
        config: The configuration.
    """

    config: McpServerConfig

    def lookup(self, server_id: str) -> McpServerConfig | None:
        """Find a server's saved configuration.

        Args:
            server_id: The server.

        Returns:
            McpServerConfig | None: The configuration, when it is this one.
        """
        return self.config if server_id == self.config.server_id else None


async def _text(connection: McpConnection, tool: str) -> str:
    """Call a fixture tool and read its text.

    Args:
        connection: The connection.
        tool: The tool.

    Returns:
        str: The tool's text result.
    """
    result = await connection.call_tool(tool, {})
    assert not result.is_error, result
    [block] = result.content
    assert isinstance(block, TextContent)
    return block.text


async def _roots_seen(connection: McpConnection) -> list[tuple[str, str | None]]:
    """Ask the server which roots it was given.

    Args:
        connection: The connection.

    Returns:
        list[tuple[str, str | None]]: Each root's URI and name.
    """
    listed: list[dict[str, str | None]] = json.loads(await _text(connection, ROOTS_TOOL))
    return [(str(entry["uri"]), entry["name"]) for entry in listed]


def _expected(*roots: tuple[Path, str]) -> list[tuple[str, str | None]]:
    """Build the roots a server should see.

    Args:
        *roots: Each folder and the name it is sent with.

    Returns:
        list[tuple[str, str | None]]: Each root's URI and name.
    """
    return [(root_uri(str(folder)), name) for folder, name in roots]


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_server_sees_the_session_and_its_own_roots_and_their_changes(tmp_path: Path, era: Era) -> None:
    """The server is told the target's, the binaries' and the operator's folders, its own, not those it is excluded from; then the new set.

    On 2025-11-25 it is also sent ``notifications/roots/list_changed`` once when they move; on 2026-07-28 it has no such notification and
    simply sees the new set the next time it asks.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    target_dir = tmp_path / "Target Dir #1"
    libs_dir = tmp_path / "libs"
    notes_dir = tmp_path / "notes \u00fc"
    own_dir = tmp_path / "server only"
    roots = McpRootSet()
    _ = roots.set_session(
        target=str(target_dir / "app.exe"),
        binaries=[str(target_dir / "app.exe"), str(libs_dir / "dep.dll")],
        folders=[str(notes_dir)],
    )
    current = _Current(
        replace(features_config(era, port=1), roots=McpRootsSpec(folders=(str(own_dir),), exclude=(str(libs_dir),))),
    )
    hooks = McpClientHooks(list_roots=roots.callback_for(current.config, current.lookup))

    async def run() -> tuple[list[tuple[str, str | None]], list[tuple[str, str | None]], list[str], bool, str]:
        """Ask for roots, change them, and ask again.

        Returns:
            tuple[list[tuple[str, str | None]], list[tuple[str, str | None]], list[str], bool, str]: The roots before and after, the
            servers found stale, whether the change was announced, and how many notices the server counted.
        """
        async with features_connection(tmp_path, era, hooks=hooks) as connection:
            first = await _roots_seen(connection)
            _ = roots.set_folders([])
            current.config = replace(current.config, roots=McpRootsSpec())
            stale = roots.stale([current.config])
            announced = await connection.announce_roots_changed()
            second = await _roots_seen(connection)
            return first, second, stale, announced, await _text(connection, ROOTS_CHANGES_TOOL)

    first, second, stale, announced, notices = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert first == _expected(
        (target_dir, "Target binary folder: Target Dir #1"),
        (notes_dir, "Session folder: notes \u00fc"),
        (own_dir, "Server folder: server only"),
    )
    assert second == _expected((target_dir, "Target binary folder: Target Dir #1"), (libs_dir, "Session binary folder: libs"))
    assert stale == ["features"]
    assert announced is (era is Era.LEGACY)
    assert notices == ("1" if era is Era.LEGACY else "0")


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_a_server_offered_no_roots_is_never_told_any(tmp_path: Path, era: Era) -> None:
    """Without a roots callback the capability is not advertised, so a server that needs roots is refused them.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """

    async def run() -> tuple[bool, bool]:
        """Ask for roots with none offered.

        Returns:
            tuple[bool, bool]: Whether the client declared roots, and whether the call failed.
        """
        async with features_connection(tmp_path, era, hooks=McpClientHooks()) as connection:
            declared = json.loads(await _text(connection, CAPABILITIES_TOOL))
            try:
                result = await connection.call_tool(ROOTS_TOOL, {})
            except McpError:
                return "roots" in declared, True
            return "roots" in declared, result.is_error

    assert asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S)) == (False, True)


@pytest.mark.parametrize(
    ("path", "uri"),
    [
        ("C:\\Program Files\\T\u00e4rget #1\\", "file:///C:/Program%20Files/T%C3%A4rget%20%231"),
        ("c:/tools/x64dbg", "file:///C:/tools/x64dbg"),
        ("C:\\", "file:///C:/"),
        ("\\\\lab-share\\samples\\in progress", "file://lab-share/samples/in%20progress"),
        ("D:\\a\\..\\b\\.\\c;d", "file:///D:/b/c%3Bd"),
    ],
)
def test_windows_paths_encode_as_file_uris(path: str, uri: str) -> None:
    """A Windows drive or UNC path becomes a ``file://`` URI with every segment percent-encoded as UTF-8.

    Args:
        path: The Windows path.
        uri: The URI it must become.
    """
    assert root_uri(path, windows=True) == uri


def test_posix_paths_encode_and_relative_paths_are_refused() -> None:
    """A POSIX path is encoded the same way; a relative or drive-relative path is not a root."""
    assert root_uri("/srv/samples/a b%", windows=False) == "file:///srv/samples/a%20b%25"
    for relative in ("samples\\x", "C:samples"):
        with pytest.raises(ValueError, match="not an absolute path"):
            _ = normalize_root_path(relative, windows=True)
    with pytest.raises(ValueError, match="not an absolute path"):
        _ = normalize_root_path("samples/x", windows=False)


def _config(**changes: object) -> McpServerConfig:
    """Build a server configuration for the root composition checks.

    Args:
        **changes: Fields to set.

    Returns:
        McpServerConfig: The configuration.
    """
    return replace(features_config(Era.MODERN), **changes)


def test_server_roots_follow_the_servers_settings(tmp_path: Path) -> None:
    """Roots off offers nothing, leaving the session out offers only the server's own, and exclusions hide session folders.

    Args:
        tmp_path: Per-test directory.
    """
    session = session_roots(target=str(tmp_path / "t" / "a.exe"), binaries=[str(tmp_path / "t" / "a.exe")], folders=[str(tmp_path / "s")])
    own = str(tmp_path / "own")
    assert server_roots(_config(roots=McpRootsSpec(enabled=False, folders=(own,))), session) == ()
    only_own = server_roots(_config(roots=McpRootsSpec(include_session=False, folders=(own,))), session)
    assert [(root.path, root.source) for root in only_own] == [(own, RootSource.SERVER)]
    hidden = server_roots(_config(roots=McpRootsSpec(exclude=(str(tmp_path / "s"),))), session)
    assert [(root.path, root.source, root.writable) for root in hidden] == [(str(tmp_path / "t"), RootSource.TARGET, None)]


def test_a_sandboxed_server_is_always_told_where_it_may_write(tmp_path: Path) -> None:
    """Every ``allowWrite`` folder is a root, even one excluded or already a session root, and each root says whether it is writable.

    Args:
        tmp_path: Per-test directory.
    """
    target = tmp_path / "t"
    scratch = tmp_path / "scratch"
    session = session_roots(target=str(target / "a.exe"), binaries=(), folders=())
    sandbox = McpSandboxSpec(enabled=True, allow_write=(str(target), str(scratch)))
    offered = server_roots(_config(sandbox=sandbox, roots=McpRootsSpec(include_session=False, exclude=(str(scratch),))), session)
    assert [(root.path, root.source, root.writable) for root in offered] == [
        (str(target), RootSource.SANDBOX, True),
        (str(scratch), RootSource.SANDBOX, True),
    ]
    with_session = server_roots(_config(sandbox=replace(sandbox, allow_write=(str(scratch),))), session)
    assert [(root.path, root.source, root.writable) for root in with_session] == [
        (str(target), RootSource.TARGET, False),
        (str(scratch), RootSource.SANDBOX, True),
    ]


def test_only_servers_that_asked_and_would_now_hear_otherwise_are_stale(tmp_path: Path) -> None:
    """A server that never asked is not told; one that asked is told once per change.

    Args:
        tmp_path: Per-test directory.
    """
    roots = McpRootSet()
    asked = _config(server_id="asked")
    never = _config(server_id="never")
    assert roots.listed(asked) == ()
    changes: list[tuple[tuple[McpRoot, ...], tuple[McpRoot, ...]]] = []
    roots.add_listener(lambda before, after: changes.append((before, after)))
    assert roots.set_folders([str(tmp_path / "new")]) is True
    assert roots.set_folders([str(tmp_path / "new")]) is False
    assert len(changes) == 1
    assert roots.stale([asked, never]) == ["asked"]
    assert roots.stale([asked, never]) == []


def test_the_session_keeps_its_folders(tmp_path: Path) -> None:
    """The operator's folders survive a save and load, and an export and import; a session saved before them loads with none.

    Args:
        tmp_path: Per-test directory.
    """
    store = SessionStore(db_path=tmp_path / "sessions.db")
    session = Session.create(provider="openai", model="m")
    older = Session.create(provider="openai", model="m")
    store.save(older)
    assert session.set_root_folders([str(tmp_path / "a"), str(tmp_path / "b")]) is True
    assert session.set_root_folders([str(tmp_path / "a"), str(tmp_path / "b")]) is False
    store.save(session)
    loaded = store.load(session.id)
    assert loaded is not None
    assert loaded.root_folders == [str(tmp_path / "a"), str(tmp_path / "b")]
    reloaded_older = store.load(older.id)
    assert reloaded_older is not None
    assert reloaded_older.root_folders == []
    exported = tmp_path / "session.json"
    store.export_to_json(session, exported)
    imported = store.import_from_json(exported)
    assert imported.root_folders == loaded.root_folders
    assert imported.updated_at <= datetime.now(tz=UTC)
