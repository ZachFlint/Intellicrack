# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 12: importing and saving keep every server, and the literal-secret check tells credentials from ids.

The gates parse and save real configuration files. Keys that collide once normalized -- differing only in case, or alike in their first
32 characters -- must all survive an import and a save, and an entry set aside as unusable must never overwrite, or be overwritten by, a
usable one. The literal-secret check must pass the ids and settings the audit found it refusing, and refuse the credentials it found it
missing.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from intellicrack.mcp.config import McpConfigStore, literal_secret_problem, unique_server_id


if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from intellicrack.mcp.config import McpServerConfig


_LONG_PREFIX = "analysis-server-for-the-reverse-engineering-lab"


def _commands(servers: Sequence[McpServerConfig]) -> dict[str, str]:
    """Map each server id to its launch command.

    Args:
        servers: The document's servers.

    Returns:
        dict[str, str]: Id to command.
    """
    commands: dict[str, str] = {}
    for server in servers:
        assert server.stdio is not None
        commands[server.server_id] = server.stdio.command
    return commands


class TestCollidingKeysSurvive:
    """Keys that normalize to the same id are all kept through import and save."""

    @pytest.mark.parametrize(
        "keys",
        [["GitHub", "github"], [f"{_LONG_PREFIX}-one", f"{_LONG_PREFIX}-two"], ["my_server", "my-server", "My Server"]],
        ids=["case", "first-32-characters", "three-ways"],
    )
    def test_import_then_save_keeps_every_server(self, tmp_path: Path, keys: list[str]) -> None:
        """Every imported server is saved, each under its own id, with its own command.

        Args:
            tmp_path: Per-test directory.
            keys: The colliding keys.
        """
        store = McpConfigStore(tmp_path / "mcp.json")
        raw = {"mcpServers": {key: {"command": f"tool-{index}"} for index, key in enumerate(keys)}}

        imported = store.import_document(json.dumps(raw))
        store.save(imported)
        reloaded = store.load()

        assert imported.rejected == ()
        assert sorted(_commands(reloaded.servers).values()) == [f"tool-{index}" for index in range(len(keys))]
        assert len(set(_commands(reloaded.servers))) == len(keys)

    def test_loaded_file_with_colliding_keys_loses_nothing_on_save(self, tmp_path: Path) -> None:
        """A file already holding ``GitHub`` and ``github`` keeps both servers after a load and a save.

        Args:
            tmp_path: Per-test directory.
        """
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps({"servers": {"GitHub": {"command": "first"}, "github": {"command": "second"}}}), encoding="utf-8")
        store = McpConfigStore(path)

        store.save(store.load())

        assert sorted(_commands(store.load().servers).values()) == ["first", "second"]

    def test_unusable_entry_and_usable_entry_under_one_id_are_both_written_back(self, tmp_path: Path) -> None:
        """An unusable ``srv`` and a usable ``SRV`` both survive a save, neither overwriting the other.

        Args:
            tmp_path: Per-test directory.
        """
        path = tmp_path / "mcp.json"
        broken = {"type": "carrier-pigeon", "url": "https://example.com"}
        path.write_text(json.dumps({"servers": {"srv": broken, "SRV": {"command": "tool"}}}), encoding="utf-8")
        store = McpConfigStore(path)

        store.save(store.load())
        written = json.loads(path.read_text(encoding="utf-8"))["servers"]

        assert written["srv"] == broken
        assert {"command": "tool"}.items() <= next(value for key, value in written.items() if key != "srv").items()

    def test_server_renamed_onto_an_unusable_entry_does_not_erase_it(self) -> None:
        """A usable server renamed to the key an unusable entry is kept under is written beside it, not over it."""
        broken = {"type": "carrier-pigeon", "url": "https://example.com"}
        document = McpConfigStore.parse_document({"servers": {"srv": broken, "other": {"command": "tool"}}}, retain_rejected=True)
        [other] = document.servers
        renamed = document.without_server("other").with_server(replace(other, server_id="srv"))

        written = McpConfigStore.serialize_document(renamed)["servers"]

        assert written["srv"]["command"] == "tool"
        assert broken in written.values()

    def test_numbered_ids_fit_the_id_limit(self) -> None:
        """A numbered id cut from a 32-character one is still a usable id and still unique."""
        base = "x" * 32
        taken = {base, f"{'x' * 30}-2"}

        assert unique_server_id(base, taken) == f"{'x' * 30}-3"
        assert unique_server_id("free", taken) == "free"


class TestLiteralSecretCheck:
    """Ids and settings pass; credentials hidden in connection strings and options are refused."""

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("AUTH_MODE", "oauth"),
            ("PRIVATE_REPO", "true"),
            ("SIGNATURE_ALGO", "rs256"),
            ("NOTION_PAGE_ID", "0123456789abcdef0123456789abcdef"),
            ("DRIVE_FOLDER", "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"),
            ("COMMIT", "0123456789abcdef0123456789abcdef01234567"),
        ],
    )
    def test_settings_and_ids_are_not_credentials(self, name: str, value: str) -> None:
        """A mode, a flag, an algorithm name and a document or commit id are accepted.

        Args:
            name: The variable name.
            value: Its value.
        """
        assert literal_secret_problem(name, value) is None

    def test_password_in_a_connection_string_is_refused(self) -> None:
        """``Password=`` inside a connection string is found and named."""
        problem = literal_secret_problem("DB_CONN", "Server=db;Password=Hunter2!")

        assert problem is not None
        assert "'Password'" in problem

    @pytest.mark.parametrize(
        "args",
        [["--password", "hunter2"], ["-p", "Sup3rS3cret!"], ["-pSup3rS3cret!"], ["--dsn", "Server=db;Pwd=Hunter2!"]],
        ids=["long-option", "short-option", "attached", "connection-string"],
    )
    def test_passwords_in_arguments_are_refused(self, args: list[str]) -> None:
        """A password after ``--password`` or ``-p``, attached to ``-p``, or inside a connection string is refused.

        Args:
            args: The launch arguments.
        """
        parsed = McpConfigStore.parse_document({"servers": {"srv": {"command": "tool", "args": args}}})

        assert parsed.servers == ()
        assert "args[" in parsed.rejected[0].reason

    @pytest.mark.parametrize(
        "args",
        [
            ["checkout", "0123456789abcdef0123456789abcdef01234567"],
            ["--page", "0123456789abcdef0123456789abcdef"],
            ["--folder", "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"],
            ["-p", "8080"],
            ["-p", "Production2024"],
            ["--auth-mode", "oauth"],
        ],
        ids=["git-sha", "notion-id", "drive-id", "port", "profile", "auth-mode"],
    )
    def test_ordinary_arguments_are_accepted(self, args: list[str]) -> None:
        """Commit and document ids, a port and a profile after ``-p``, and a mode are accepted.

        Args:
            args: The launch arguments.
        """
        parsed = McpConfigStore.parse_document({"servers": {"srv": {"command": "tool", "args": args}}})

        assert parsed.rejected == (), parsed.rejected[0].reason if parsed.rejected else ""
