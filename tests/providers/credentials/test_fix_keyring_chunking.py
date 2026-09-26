# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for storing credentials larger than one Credential Manager blob, and for reporting keyring read failures.

Windows Credential Manager refuses a generic credential whose blob exceeds ``CRED_MAX_CREDENTIAL_BLOB_SIZE`` (2560 bytes), and keyring's
Windows backend writes UTF-16, so any secret over about 1280 characters -- an OAuth token record, a JWT-bearing input -- used to fail to
store. The platform-independent tests run against a real file-backed keyring (``keyrings.alt``) in a private temporary file; the
Credential Manager variant adds the same blob limit Windows enforces, so the chunking is proven against the constraint it exists for. The
tests at the bottom run against the real Windows Credential Manager and only there.
"""

from __future__ import annotations

import asyncio
import base64
import configparser
import hashlib
import json
import sys
import uuid
from typing import TYPE_CHECKING, Final, cast

import keyring
import pytest

from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials import store as store_module
from intellicrack.credentials.store import (
    CRED_MAX_CREDENTIAL_BLOB_BYTES,
    ChunkManifest,
    CredentialStore,
    CredentialStoreError,
    KeyringReadError,
    credential_blob_size,
    split_credential_blob,
)
from intellicrack.mcp.auth import credential_key, has_stored_credentials
from intellicrack.mcp.errors import McpAuthError, McpConfigError
from intellicrack.mcp.secrets import McpSecretResolver, input_credential_key
from tests._helpers.private_keyring import (
    CredentialManagerSizedKeyring,
    file_keyring_entry_name,
    installed_keyring,
    private_file_keyring,
)


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from keyring.backend import KeyringBackend

    from tests._helpers.private_keyring import SecretBackend


_LARGE_SECRET_CHARS = 9000
"""Well past one blob: about 18 KB once encoded as UTF-16."""


_MANIFEST_MARKER_FIELD: Final[str] = "intellicrack_chunked_credential"
"""Field that marks a stored entry as a chunk manifest."""


def _isolated_store(backend: KeyringBackend, monkeypatch: pytest.MonkeyPatch) -> Iterator[CredentialStore]:
    """Install ``backend`` and build a store on a private service name.

    Args:
        backend: The backend to install.
        monkeypatch: Restores the service name afterwards.

    Yields:
        CredentialStore: A store writing only to ``backend``.
    """
    monkeypatch.setattr(CredentialStore, "SERVICE_NAME", f"intellicrack-chunk-{uuid.uuid4().hex}")
    with installed_keyring(backend):
        store = CredentialStore()
        assert store.keyring_available
        yield store


@pytest.fixture
def keyring_file(tmp_path: Path) -> Path:
    """The private keyring file.

    Args:
        tmp_path: Per-test directory.

    Returns:
        Path: The file the backend writes.
    """
    return tmp_path / "keyring_pass.cfg"


@pytest.fixture
def sized_backend(keyring_file: Path) -> CredentialManagerSizedKeyring:
    """A Credential-Manager-sized keyring over the private file.

    Args:
        keyring_file: The private keyring file.

    Returns:
        CredentialManagerSizedKeyring: The backend.
    """
    return CredentialManagerSizedKeyring(keyring_file)


@pytest.fixture
def sized_store(sized_backend: CredentialManagerSizedKeyring, monkeypatch: pytest.MonkeyPatch) -> Iterator[CredentialStore]:
    """A credential store over the Credential-Manager-sized keyring.

    Args:
        sized_backend: The backend.
        monkeypatch: Restores the service name afterwards.

    Yields:
        CredentialStore: The store.
    """
    yield from _isolated_store(sized_backend, monkeypatch)


def _key(store: CredentialStore, provider: str) -> str:
    """The keyring entry name the store files a provider under.

    Args:
        store: The store.
        provider: The provider or credential key.

    Returns:
        str: The keyring entry name.
    """
    return f"{store.SERVICE_NAME}_{provider}"


class TestSplitting:
    """The pure splitting logic keeps every piece inside the blob limit and loses nothing."""

    def test_pieces_fit_and_rejoin(self) -> None:
        """A long ASCII value splits into pieces that each fit and rejoin exactly."""
        value = "".join(chr(0x41 + index % 26) for index in range(_LARGE_SECRET_CHARS))
        pieces = split_credential_blob(value)
        assert "".join(pieces) == value
        assert len(pieces) > 1
        assert all(credential_blob_size(piece) <= CRED_MAX_CREDENTIAL_BLOB_BYTES for piece in pieces)
        assert all(len(piece.encode("utf-16-le")) == credential_blob_size(piece) for piece in pieces)

    def test_surrogate_pairs_are_never_divided(self) -> None:
        """Characters outside the BMP take four bytes and never straddle two pieces."""
        value = "a" + "\U0001f511" * 2000
        pieces = split_credential_blob(value, max_bytes=10)
        assert "".join(pieces) == value
        assert all(len(piece.encode("utf-16-le")) <= 10 for piece in pieces)

    def test_exact_limit_is_one_piece(self) -> None:
        """A value of exactly the limit is not split."""
        value = "x" * (CRED_MAX_CREDENTIAL_BLOB_BYTES // 2)
        assert split_credential_blob(value) == [value]

    def test_manifest_round_trips(self) -> None:
        """A manifest parses back to itself and an ordinary value is not mistaken for one."""
        manifest = ChunkManifest(generation="0a1b2c3d", count=3, length=3000)
        assert ChunkManifest.parse(manifest.serialize()) == manifest
        assert ChunkManifest.parse('{"api_key": "x"}') is None


class TestLargeCredentialStorage:
    """A credential over the Credential Manager blob limit stores, reads back and deletes cleanly."""

    def test_large_secret_round_trips(self, sized_store: CredentialStore) -> None:
        """A secret of about 18 KB in UTF-16 is stored and read back intact.

        Args:
            sized_store: Store over the Credential-Manager-sized keyring.
        """
        secret = "tok-" + "Zq9" * (_LARGE_SECRET_CHARS // 3)

        async def round_trip() -> ProviderCredentials | None:
            await sized_store.set("mcp:oauth:big:tokens", ProviderCredentials(api_key=secret))
            return await sized_store.get_secret("mcp:oauth:big:tokens")

        loaded = asyncio.run(round_trip())
        assert loaded is not None
        assert loaded.api_key == secret

    def test_every_entry_written_fits_one_blob(self, sized_store: CredentialStore, keyring_file: Path) -> None:
        """No entry the store writes exceeds the Credential Manager limit.

        Args:
            sized_store: Store over the Credential-Manager-sized keyring.
            keyring_file: The keyring file, read directly.
        """
        secret = "é" * _LARGE_SECRET_CHARS
        asyncio.run(sized_store.set("wide", ProviderCredentials(api_key=secret)))
        parser = configparser.RawConfigParser()
        parser.read(keyring_file, encoding="utf-8")
        section = file_keyring_entry_name(sized_store.SERVICE_NAME)
        values = [base64.decodebytes(parser.get(section, option).encode()).decode("utf-8") for option in parser.options(section)]
        assert len(values) > 2
        assert all(credential_blob_size(value) <= CRED_MAX_CREDENTIAL_BLOB_BYTES for value in values)

    def test_shrinking_and_deleting_leave_no_chunks(
        self,
        sized_store: CredentialStore,
        sized_backend: CredentialManagerSizedKeyring,
    ) -> None:
        """Overwriting a chunked value with a small one, then deleting, removes every chunk entry.

        Args:
            sized_store: Store over the Credential-Manager-sized keyring.
            sized_backend: The backend, read directly.
        """
        key = _key(sized_store, "shrink")
        asyncio.run(sized_store.set("shrink", ProviderCredentials(api_key="L" * _LARGE_SECRET_CHARS)))
        stored = sized_backend.get_password(sized_store.SERVICE_NAME, key)
        assert stored is not None
        manifest = ChunkManifest.parse(stored)
        assert manifest is not None
        chunk_keys = [manifest.chunk_key(key, index) for index in range(manifest.count)]
        assert all(sized_backend.get_password(sized_store.SERVICE_NAME, chunk) is not None for chunk in chunk_keys)

        asyncio.run(sized_store.set("shrink", ProviderCredentials(api_key="small")))
        assert all(sized_backend.get_password(sized_store.SERVICE_NAME, chunk) is None for chunk in chunk_keys)
        loaded = asyncio.run(sized_store.get_secret("shrink"))
        assert loaded is not None
        assert loaded.api_key == "small"

        asyncio.run(sized_store.set("shrink", ProviderCredentials(api_key="M" * _LARGE_SECRET_CHARS)))
        second = ChunkManifest.parse(sized_backend.get_password(sized_store.SERVICE_NAME, key) or "")
        assert second is not None
        assert asyncio.run(sized_store.delete("shrink")) is True
        assert sized_backend.get_password(sized_store.SERVICE_NAME, key) is None
        assert all(
            sized_backend.get_password(sized_store.SERVICE_NAME, second.chunk_key(key, index)) is None for index in range(second.count)
        )

    def test_mcp_input_over_the_limit_is_stored(self, sized_store: CredentialStore) -> None:
        """``McpSecretResolver.set_input`` stores and resolves a value larger than one blob.

        Args:
            sized_store: Store over the Credential-Manager-sized keyring.
        """
        resolver = McpSecretResolver(sized_store)
        value = "eyJ" + "a1B2" * 1500

        async def run() -> str:
            await resolver.set_input("jwt", value)
            return await resolver.resolve("Bearer ${input:jwt}")

        assert asyncio.run(run()) == f"Bearer {value}"


class TestReadFailuresAreReported:
    """A keyring entry that exists but cannot be read raises instead of reading as "not stored"."""

    def test_missing_chunk_raises(self, sized_store: CredentialStore, sized_backend: CredentialManagerSizedKeyring) -> None:
        """A manifest whose chunk has gone raises :class:`KeyringReadError`.

        Args:
            sized_store: Store over the Credential-Manager-sized keyring.
            sized_backend: The backend, edited directly.
        """
        key = _key(sized_store, "torn")
        asyncio.run(sized_store.set("torn", ProviderCredentials(api_key="T" * _LARGE_SECRET_CHARS)))
        manifest = ChunkManifest.parse(sized_backend.get_password(sized_store.SERVICE_NAME, key) or "")
        assert manifest is not None
        sized_backend.delete_password(sized_store.SERVICE_NAME, manifest.chunk_key(key, 1))
        with pytest.raises(KeyringReadError, match="part 1 is missing"):
            asyncio.run(sized_store.get_secret("torn"))

    def test_shortened_chunk_raises(self, sized_store: CredentialStore, sized_backend: CredentialManagerSizedKeyring) -> None:
        """A chunk rewritten shorter fails the reassembly check instead of reading as a valid secret.

        Args:
            sized_store: Store over the Credential-Manager-sized keyring.
            sized_backend: The backend, edited directly.
        """
        key = _key(sized_store, "short")
        asyncio.run(sized_store.set("short", ProviderCredentials(api_key="S" * _LARGE_SECRET_CHARS)))
        manifest = ChunkManifest.parse(sized_backend.get_password(sized_store.SERVICE_NAME, key) or "")
        assert manifest is not None
        chunk_key = manifest.chunk_key(key, 1)
        original = sized_backend.get_password(sized_store.SERVICE_NAME, chunk_key)
        assert original is not None
        cast("SecretBackend", sized_backend).set_password(sized_store.SERVICE_NAME, chunk_key, original[:-7])
        with pytest.raises(KeyringReadError, match="not its recorded length"):
            asyncio.run(sized_store.get_secret("short"))

    def test_manifest_holds_nothing_derived_from_the_secret(
        self,
        sized_store: CredentialStore,
        sized_backend: CredentialManagerSizedKeyring,
    ) -> None:
        """The manifest stores only its generation, part count and length -- no hash of the secret.

        An unsalted digest of the secret beside its chunks would be a fast
        offline guess-checker for anyone who can read the manifest.

        Args:
            sized_store: Store over the Credential-Manager-sized keyring.
            sized_backend: The backend, edited directly.
        """
        secret = "sk-" + "Q" * _LARGE_SECRET_CHARS
        asyncio.run(sized_store.set("plain", ProviderCredentials(api_key=secret)))
        stored = sized_backend.get_password(sized_store.SERVICE_NAME, _key(sized_store, "plain"))
        assert stored is not None
        fields = cast("dict[str, object]", json.loads(stored))
        assert set(fields) == {_MANIFEST_MARKER_FIELD, "generation", "count", "length"}
        for algorithm in ("md5", "sha1", "sha256", "sha512", "blake2b"):
            assert hashlib.new(algorithm, secret.encode()).hexdigest() not in stored

    def test_undecodable_entry_raises_mcp_auth_error(
        self,
        sized_store: CredentialStore,
        keyring_file: Path,
    ) -> None:
        """A stored input the backend cannot decode is an error, not a missing value.

        The entry is written to the keyring file as base64 of bytes that are
        not UTF-8, so the backend's own ``get_password`` fails. Before the fix
        the store logged that and answered ``None``, and the operator was told
        to enter the value again.

        Args:
            sized_store: Store over the Credential-Manager-sized keyring.
            keyring_file: The keyring file, edited directly.
        """
        resolver = McpSecretResolver(sized_store)
        asyncio.run(resolver.set_input("gh", "ghp-value"))
        parser = configparser.RawConfigParser()
        parser.read(keyring_file, encoding="utf-8")
        section = file_keyring_entry_name(sized_store.SERVICE_NAME)
        option = file_keyring_entry_name(_key(sized_store, input_credential_key("gh")))
        parser.set(section, option, "\n" + base64.encodebytes(b"\xff\xfe\xfd").decode())
        with keyring_file.open("w", encoding="utf-8") as handle:
            parser.write(handle)

        with pytest.raises(McpAuthError, match="cannot read MCP input 'gh'"):
            asyncio.run(resolver.has_input("gh"))
        with pytest.raises(McpAuthError, match="cannot read MCP input 'gh' from the keyring"):
            asyncio.run(resolver.resolve("${input:gh}"))

        asyncio.run(resolver.set_input("gh", "ghp-replacement"))
        assert asyncio.run(resolver.resolve("${input:gh}")) == "ghp-replacement"

    def test_corrupt_payload_raises_for_oauth_state(
        self,
        sized_store: CredentialStore,
    ) -> None:
        """A token entry holding something other than the store's JSON is a read failure.

        Args:
            sized_store: Store over the Credential-Manager-sized keyring.
        """
        key = credential_key("srv", "https://example.com", "tokens")
        keyring.set_password(sized_store.SERVICE_NAME, _key(sized_store, key), "{not json")
        with pytest.raises(KeyringReadError):
            asyncio.run(sized_store.get_secret(key))
        with pytest.raises(McpAuthError, match="cannot check OAuth state"):
            asyncio.run(has_stored_credentials(sized_store, "srv", "https://example.com"))

    def test_absent_input_is_still_reported_missing(self, sized_store: CredentialStore) -> None:
        """An input that was never stored is still a configuration problem, not a keyring failure.

        Args:
            sized_store: Store over the Credential-Manager-sized keyring.
        """
        resolver = McpSecretResolver(sized_store)
        assert asyncio.run(resolver.has_input("never")) is False
        with pytest.raises(McpConfigError, match="no value stored"):
            asyncio.run(resolver.resolve("${input:never}"))


class TestStoreFailureMessage:
    """A keyring that refuses a write is reported as a refusal, not as a missing package."""

    def test_set_input_failure_does_not_blame_a_missing_package(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The keyring file cannot be written, and the message says so rather than "install keyring".

        Args:
            tmp_path: Per-test directory.
            monkeypatch: Restores the service name afterwards.
        """
        unwritable = tmp_path / "is-a-directory"
        unwritable.mkdir()
        for store in _isolated_store(private_file_keyring(unwritable), monkeypatch):
            resolver = McpSecretResolver(store)
            with pytest.raises(McpAuthError) as caught:
                asyncio.run(resolver.set_input("gh", "value"))
            text = str(caught.value)
            assert "keyring refused" in text
            assert "Install" not in text
            assert isinstance(caught.value.__cause__, CredentialStoreError)


_WINDOWS_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows Credential Manager rejects a generic credential blob over CRED_MAX_CREDENTIAL_BLOB_SIZE (2560 bytes)",
)


@pytest.fixture
def credential_manager_store(monkeypatch: pytest.MonkeyPatch) -> CredentialStore:
    """A store over the real Windows Credential Manager on a throwaway service name.

    Args:
        monkeypatch: Restores the service name afterwards.

    Returns:
        CredentialStore: The store.
    """
    monkeypatch.setattr(CredentialStore, "SERVICE_NAME", f"intellicrack-chunk-{uuid.uuid4().hex}")
    store = CredentialStore()
    if not store.keyring_available:
        pytest.fail("the Windows Credential Manager backend is not available")
    return store


@_WINDOWS_ONLY
def test_credential_manager_round_trips_a_large_token(credential_manager_store: CredentialStore) -> None:
    """A token record far over the blob limit stores, reads back and deletes through Credential Manager.

    Args:
        credential_manager_store: Store over the Windows Credential Manager.
    """
    secret = "tok-" + "Zq9" * (_LARGE_SECRET_CHARS // 3)

    async def round_trip() -> tuple[str | None, bool, ProviderCredentials | None]:
        await credential_manager_store.set("mcp:oauth:big:tokens", ProviderCredentials(api_key=secret))
        loaded = await credential_manager_store.get_secret("mcp:oauth:big:tokens")
        removed = await credential_manager_store.delete("mcp:oauth:big:tokens")
        after = await credential_manager_store.get_secret("mcp:oauth:big:tokens")
        return (loaded.api_key if loaded is not None else None), removed, after

    loaded, removed, after = asyncio.run(round_trip())
    assert loaded == secret
    assert removed is True
    assert after is None


def test_store_module_exports_the_limit() -> None:
    """The limit constant is Credential Manager's documented 5 * 512 bytes."""
    assert store_module.CRED_MAX_CREDENTIAL_BLOB_BYTES == 2560
