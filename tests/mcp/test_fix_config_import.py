# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for importing ``mcp.json`` written by other clients.

Import used to reject valid input (keys such as ``GitHub`` or ``my_server``, the ``streamable-http`` transport name, URLs, paths and UUIDs
that merely sat under a credential-sounding name) and to accept invalid input (literal keys in ``args``). One bad server key also threw
away the whole document, and a ``${input:x}`` reference in ``args`` parsed but was never resolved, so the launch refused it.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import (
    McpConfigStore,
    McpServerConfig,
    McpTransportKind,
    StdioServerSpec,
    missing_input_ids,
    normalize_server_id,
)
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.consent import McpConsentGate, TrustStore
from intellicrack.mcp.errors import McpConfigError
from intellicrack.mcp.secrets import McpSecretResolver
from tests._helpers.private_keyring import installed_keyring, private_file_keyring


if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping


_SERVER_SCRIPT = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_server_main.py"
_CONNECT_TIMEOUT_S = 60.0
_TEARDOWN_TIMEOUT_S = 15.0


def _parse(document: Mapping[str, object]) -> list[str]:
    """Parse a document and list the ids of the servers it kept.

    Args:
        document: The decoded document.

    Returns:
        list[str]: Kept server ids, in order.
    """
    return [server.server_id for server in McpConfigStore.parse_document(document).servers]


class TestServerKeys:
    """Keys written in another client's style are normalized, and one bad entry costs only itself."""

    def test_mixed_case_and_underscore_keys_are_normalized(self) -> None:
        """``GitHub`` and ``my_server`` become ``github`` and ``my-server``."""
        document = {"mcpServers": {"GitHub": {"command": "gh-mcp"}, "my_server": {"url": "https://example.com/mcp"}}}
        assert _parse(document) == ["github", "my-server"]
        assert normalize_server_id("Some.Server Name") == "some-server-name"
        assert normalize_server_id("___") is None
        assert normalize_server_id("x" * 40) == "x" * 32

    def test_one_bad_entry_does_not_reject_the_document(self) -> None:
        """A server with an unknown transport is set aside with its reason; the others are kept."""
        parsed = McpConfigStore.parse_document({
            "servers": {
                "good": {"command": "tool"},
                "broken": {"type": "carrier-pigeon", "url": "https://example.com"},
                "!!!": {"command": "tool"},
            },
        })
        assert [server.server_id for server in parsed.servers] == ["good"]
        reasons = {entry.key: entry.reason for entry in parsed.rejected}
        assert set(reasons) == {"broken", "!!!"}
        assert "carrier-pigeon" in reasons["broken"]

    def test_keys_that_collide_after_normalizing_keep_the_first(self) -> None:
        """``my_server`` and ``my-server`` cannot both be ``my-server``; the second is reported."""
        parsed = McpConfigStore.parse_document({"servers": {"my_server": {"command": "a"}, "my-server": {"command": "b"}}})
        assert [server.server_id for server in parsed.servers] == ["my-server"]
        assert parsed.servers[0].stdio is not None
        assert parsed.servers[0].stdio.command == "a"
        assert [entry.key for entry in parsed.rejected] == ["my-server"]

    def test_import_with_nothing_usable_is_an_error(self) -> None:
        """Pasting a document where no server can be used says why instead of importing nothing."""
        with pytest.raises(McpConfigError, match="no server in the imported MCP configuration can be used"):
            McpConfigStore().import_document(json.dumps({"servers": {"x": {"type": "bogus", "command": "a"}}}))

    def test_rejected_entries_in_the_file_survive_a_save(self, tmp_path: Path) -> None:
        """Saving after a load writes back the entries that were set aside, unchanged.

        Args:
            tmp_path: Per-test directory.
        """
        path = tmp_path / "mcp.json"
        broken = {"type": "bogus", "command": "a"}
        path.write_text(json.dumps({"servers": {"Good": {"command": "tool"}, "broken": broken}}), encoding="utf-8")
        store = McpConfigStore(path)
        document = store.load()
        assert [server.server_id for server in document.servers] == ["good"]
        store.save(document)
        written = json.loads(path.read_text(encoding="utf-8"))
        assert written["servers"]["broken"] == broken
        assert written["servers"]["good"]["command"] == "tool"

    def test_imported_rejected_entries_are_not_written(self, tmp_path: Path) -> None:
        """An imported entry refused for a literal credential never reaches the file.

        Args:
            tmp_path: Per-test directory.
        """
        store = McpConfigStore(tmp_path / "mcp.json")
        document = store.import_document(
            json.dumps({
                "servers": {"ok": {"command": "tool"}, "leaky": {"command": "tool", "env": {"API_KEY": "sk-abcdefghijklmnopqrstuvwx"}}},
            }),
        )
        store.save(document)
        text = (tmp_path / "mcp.json").read_text(encoding="utf-8")
        assert "sk-abcdefghijklmnop" not in text
        assert "leaky" not in text


class TestTransportNames:
    """The names other clients use for Streamable HTTP are accepted."""

    @pytest.mark.parametrize("declared", ["streamable-http", "streamableHttp", "streamable_http", "HTTP", "http"])
    def test_streamable_http_spellings(self, declared: str) -> None:
        """Every spelling of Streamable HTTP parses as the HTTP transport.

        Args:
            declared: The declared ``type``.
        """
        parsed = McpConfigStore.parse_document({"servers": {"remote": {"type": declared, "url": "https://example.com/mcp"}}})
        assert parsed.rejected == ()
        assert parsed.servers[0].kind is McpTransportKind.HTTP

    def test_sse_and_stdio_still_parse(self) -> None:
        """The existing names keep their meaning."""
        parsed = McpConfigStore.parse_document({
            "servers": {"a": {"type": "SSE", "url": "https://example.com/sse"}, "b": {"type": "stdio", "command": "x"}},
        })
        assert [server.kind for server in parsed.servers] == [McpTransportKind.SSE, McpTransportKind.STDIO]


class TestLiteralSecretHeuristics:
    """Locations are not credentials; credentials are still refused wherever they sit."""

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("TOKEN_URL", "https://login.example.com/oauth2/v2.0/token"),
            ("AUTH_SERVER", "https://auth.example.com/realms/Intellicrack2024Production"),
            ("KEY_FILE", r"C:\Users\Operator\AppData\Roaming\Intellicrack\Keys\ServiceAccount2024.json"),
            ("GOOGLE_APPLICATION_CREDENTIALS", "/home/operator/.config/gcloud/ApplicationDefault2024Credentials.json"),
            ("PRIVATE_KEY_PATH", "~/keys/deploy_ed25519"),
            ("SECRET_STORE", "./vault/SecretsBackendConfig2024.yaml"),
            ("PROJECT_ID", "3f2b8c1e-9a4d-4e7b-8c21-5d6f7a8b9c0d"),
            ("MODEL_DIR", "/opt/Models/Qwen2Point5Coder32BInstruct/weights"),
        ],
    )
    def test_urls_paths_and_uuids_are_accepted(self, name: str, value: str) -> None:
        """A URL, a path or a UUID under any name is not a literal credential.

        Args:
            name: The environment variable name.
            value: The value.
        """
        parsed = McpConfigStore.parse_document({"servers": {"srv": {"command": "tool", "env": {name: value}}}})
        assert parsed.rejected == (), parsed.rejected[0].reason if parsed.rejected else ""

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("ENDPOINT", "https://user:hunter2hunter2@db.example.com/mcp"),
            ("ENDPOINT", "https://api.example.com/v1?api_key=abcd1234efgh5678"),
            ("API_KEY", "3f2b8c1e-9a4d-4e7b-8c21-5d6f7a8b9c0d"),
            ("GITHUB_TOKEN", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        ],
    )
    def test_embedded_and_named_credentials_are_refused(self, name: str, value: str) -> None:
        """A URL carrying a credential, or a UUID under a key name, is still refused.

        Args:
            name: The environment variable name.
            value: The value.
        """
        parsed = McpConfigStore.parse_document({"servers": {"srv": {"command": "tool", "env": {name: value}}}})
        assert parsed.servers == ()
        assert "credential" in parsed.rejected[0].reason or "literal secret" in parsed.rejected[0].reason


class TestArgumentSecrets:
    """Launch arguments get the same literal-credential check as the environment."""

    @pytest.mark.parametrize(
        "args",
        [
            ["--api-key", "sk-proj-abcdefghijklmnopqrstuvwx"],
            ["--api-key=Zx81kQpLm20RtY"],
            ["run", "-e", "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789"],
            ["--token", "a1b2c3d4e5f6g7h8"],
            ["serve", "xoxb-1234567890-abcdefghij"],
        ],
    )
    def test_literal_credentials_in_args_are_refused(self, args: list[str]) -> None:
        """A key passed on the command line is refused with its position named.

        Args:
            args: The launch arguments.
        """
        parsed = McpConfigStore.parse_document({"servers": {"srv": {"command": "tool", "args": args}}})
        assert parsed.servers == ()
        assert "args[" in parsed.rejected[0].reason

    @pytest.mark.parametrize(
        "args",
        [
            ["--api-key", "${input:key}"],
            ["--api-key=${input:key}"],
            ["-e", "GITHUB_TOKEN"],
            ["--auth", "server.py"],
            ["--token-file", "/run/secrets/token"],
            ["--verbose", "--port", "8080", "server.py"],
        ],
    )
    def test_references_and_ordinary_arguments_are_accepted(self, args: list[str]) -> None:
        """References, pass-through names, switches and paths are not literal credentials.

        Args:
            args: The launch arguments.
        """
        parsed = McpConfigStore.parse_document({"servers": {"srv": {"command": "tool", "args": args}}})
        assert parsed.rejected == (), parsed.rejected[0].reason if parsed.rejected else ""

    def test_references_in_args_are_declared_inputs(self) -> None:
        """An ``${input:x}`` in ``args`` counts as a referenced input, so the operator is asked for it."""
        document = McpConfigStore.parse_document({"servers": {"srv": {"command": "tool", "args": ["--key", "${input:cli-key}"]}}})
        assert document.servers[0].input_ids() == ("cli-key",)
        assert missing_input_ids(document) == ("cli-key",)


@pytest.fixture
def private_store(tmp_path: Path) -> Iterator[CredentialStore]:
    """A credential store over a private file keyring.

    Args:
        tmp_path: Per-test directory.

    Yields:
        CredentialStore: The store.
    """
    with installed_keyring(private_file_keyring(tmp_path / "keyring_pass.cfg")):
        yield CredentialStore()


def test_input_reference_in_args_is_resolved_at_launch(tmp_path: Path, private_store: CredentialStore) -> None:
    """A real stdio server launched with ``--mode ${input:mode}`` receives the stored value.

    The fixture server refuses an unknown ``--mode`` and the launcher refuses
    an unresolved reference, so the catalog only comes back if the argument
    was expanded from the keyring.

    Args:
        tmp_path: Per-test directory.
        private_store: Store over a private keyring.
    """
    resolver = McpSecretResolver(private_store)
    asyncio.run(resolver.set_input("mode", "well_behaved"))
    spec = StdioServerSpec(command=sys.executable, args=(str(_SERVER_SCRIPT), "--mode", "${input:mode}"))
    config = McpServerConfig(server_id="argref", kind=McpTransportKind.STDIO, stdio=spec, enabled=True, request_timeout_s=30.0)
    config.validate()

    def approve(_config: McpServerConfig, _rendered: str, _findings: object) -> bool:
        """Approve the launch.

        Args:
            _config: The server being launched.
            _rendered: The rendered launch description.
            _findings: Dangerous patterns found in the command.

        Returns:
            bool: Always ``True``.
        """
        return True

    connection = McpConnection(config, resolver, consent=McpConsentGate(TrustStore(tmp_path / "trust.json"), approve))

    async def run() -> int:
        await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
        try:
            catalog = connection.catalog
            assert catalog is not None
            return catalog.tool_count
        finally:
            await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

    assert asyncio.run(run()) > 0
