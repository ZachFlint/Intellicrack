# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave-5 falsifiable gates for CredentialStore — ops #70, #74, #76, #78, #79, #80, #83, #85, #88.

Each test asserts exact values against an independent oracle (enum literals,
provider.value strings, boolean constants) so that the named one-line mutation
listed in each docstring would turn the test red.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, cast

import pytest

from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import (
    CredentialSource,
    CredentialStore,
    KeyringUnavailableError,
    StoredCredential,
)


def _make_keyring_free_store(env_entries: dict[str, str] | None = None) -> CredentialStore:
    """Create a CredentialStore with keyring disabled and controlled env entries.

    Args:
        env_entries: Variable-name-to-value pairs injected into the fallback
            CredentialLoader without touching os.environ or disk.

    Returns:
        CredentialStore: A store whose keyring_available is always False,
        falling back only to the injected env entries.
    """
    loader = CredentialLoader(env_path=Path("/__nonexistent_wave5_gate__/.env"))
    if env_entries:
        loader_any: Any = cast(Any, loader)
        env_vars: dict[str, str] = loader_any._env_vars
        env_vars |= env_entries
    store = CredentialStore(fallback_loader=loader)
    store_any: Any = cast(Any, store)
    store_any._keyring_checked = True
    store_any._keyring_available = False
    return store


def _make_keyring_available_store(env_entries: dict[str, str] | None = None) -> CredentialStore:
    """Create a CredentialStore reporting keyring as available, with controlled env.

    The store's keyring presence guard is satisfied (so keyring-gated branches
    execute) while its env fallback contains only the injected entries.

    Args:
        env_entries: Variable-name-to-value pairs injected into the fallback
            CredentialLoader without touching os.environ or disk.

    Returns:
        CredentialStore: A store whose keyring_available is always True,
        falling back only to the injected env entries.
    """
    loader = CredentialLoader(env_path=Path("/__nonexistent_wave5_gate__/.env"))
    if env_entries:
        loader_any: Any = cast(Any, loader)
        env_vars: dict[str, str] = loader_any._env_vars
        env_vars |= env_entries
    store = CredentialStore(fallback_loader=loader)
    store_any: Any = cast(Any, store)
    store_any._keyring_checked = True
    store_any._keyring_available = True
    return store


def _clear_ollama_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove ambient OLLAMA credential variables from os.environ.

    The test sandbox container ships provider keys in os.environ, and the
    CredentialLoader falls back to os.environ; clearing OLLAMA_API_KEY makes
    the "no credential" precondition genuinely hold.

    Args:
        monkeypatch: pytest monkeypatch fixture used to delete the variables.
    """
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)


def test_deserialize_metadata_corrupt_fallback() -> None:
    """_deserialize_metadata with corrupt JSON falls back to a default StoredCredential.

    Mutation: removing the except block and re-raising would change the outcome
    from a valid fallback StoredCredential to an uncaught exception.
    """
    result: StoredCredential = cast(Any, CredentialStore)._deserialize_metadata(
        "not-valid-json{{{",
        ProviderName.ANTHROPIC,
    )
    assert result.provider is ProviderName.ANTHROPIC
    assert result.key_name == ProviderName.ANTHROPIC.value
    assert result.source is CredentialSource.KEYRING


def test_set_keyring_unavailable_raises() -> None:
    """set() raises KeyringUnavailableError when keyring_available is False.

    Mutation: removing the early-return guard would let the code proceed to
    _set_to_keyring where self._keyring is None, raising AttributeError instead
    of the expected KeyringUnavailableError.
    """
    store = _make_keyring_free_store()
    creds = ProviderCredentials(api_key="sk-ant-test-wave5")
    with pytest.raises(KeyringUnavailableError, match=r"(?i)keyring.*not.*available|not available"):
        asyncio.run(store.set(ProviderName.ANTHROPIC, creds))


def test_delete_keyring_unavailable_raises() -> None:
    """delete() raises KeyringUnavailableError when keyring_available is False.

    Mutation: swallowing the KeyringUnavailableError and returning False
    instead of raising would make this test pass vacuously.
    """
    store = _make_keyring_free_store()
    with pytest.raises(KeyringUnavailableError, match=r"(?i)keyring.*not.*available|not available"):
        asyncio.run(store.delete(ProviderName.ANTHROPIC))


def test_delete_credential_not_found_returns_false() -> None:
    """delete() returns False when no credential for the provider exists in the keyring.

    Skipped when no real keyring backend is available.

    Mutation: returning True unconditionally turns the second-call assertion red.
    """
    store = CredentialStore()
    if not store.keyring_available:
        pytest.skip("no real keyring backend available on this host")

    async def _run() -> bool:
        await store.delete(ProviderName.OLLAMA)
        return await store.delete(ProviderName.OLLAMA)

    result = asyncio.run(_run())
    assert result is False


def test_list_providers_entry_content() -> None:
    """list_providers() returns a StoredCredential with exact provider and source fields.

    Seeds an OLLAMA env entry and asserts the returned entry has
    provider==ProviderName.OLLAMA and source==CredentialSource.ENV_FILE
    (the keyring-free fallback path).

    Mutation: removing the metadata-assembly loop and returning [] always leaves
    the isinstance check green but fails this field-level assertion.
    """
    store = _make_keyring_free_store(
        env_entries={"OLLAMA_API_KEY": "wave5-ollama-sentinel"},
    )

    async def _run() -> list[StoredCredential]:
        return await store.list_providers()

    results = asyncio.run(_run())
    providers = [e.provider for e in results]
    assert ProviderName.OLLAMA in providers
    ollama_entry = next(e for e in results if e.provider is ProviderName.OLLAMA)
    assert ollama_entry.source is CredentialSource.ENV_FILE


def test_migrate_from_env_keyring_unavailable_raises() -> None:
    """migrate_from_env() raises KeyringUnavailableError when keyring is absent.

    Mutation: removing the early guard and letting migration proceed silently
    would drop the error and make the test fail with DID NOT RAISE.
    """
    store = _make_keyring_free_store(
        env_entries={"OLLAMA_API_KEY": "wave5-migrate-test"},
    )
    with pytest.raises(
        KeyringUnavailableError,
        match=r"(?i)keyring.*not.*available|not available|migration",
    ):
        asyncio.run(store.migrate_from_env([ProviderName.OLLAMA]))


def test_migrate_from_env_missing_key_result_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """migrate_from_env() maps a provider to False when its env var is absent.

    Keyring is reported available so the missing-key branch (store.py:601) is
    reached rather than the unavailable guard (store.py:593).

    Args:
        monkeypatch: pytest fixture used to clear ambient OLLAMA env vars.

    Mutation: defaulting missing providers to True instead of False turns
    the False assertion red.
    """
    _clear_ollama_env(monkeypatch)
    store = _make_keyring_available_store()

    async def _run() -> dict[ProviderName, bool]:
        return await store.migrate_from_env([ProviderName.OLLAMA])

    result = asyncio.run(_run())
    assert result[ProviderName.OLLAMA] is False


def test_validate_no_credentials_returns_false_with_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """validate() returns (False, non-empty message) when no credential exists.

    Args:
        monkeypatch: pytest fixture used to clear ambient OLLAMA env vars.

    Mutation: returning (True, None) unconditionally makes the False assertion red.
    """
    _clear_ollama_env(monkeypatch)
    store = _make_keyring_free_store()

    async def _run() -> tuple[bool, str | None]:
        return await store.validate(ProviderName.OLLAMA)

    valid, message = asyncio.run(_run())
    assert valid is False
    assert message is not None
    assert len(message) > 0


def test_get_source_no_credential_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_source() returns None when no credential exists anywhere.

    Args:
        monkeypatch: pytest fixture used to clear ambient OLLAMA env vars.

    Mutation: returning CredentialSource.KEYRING as a default turns the
    None assertion red.
    """
    _clear_ollama_env(monkeypatch)
    store = _make_keyring_free_store()

    async def _run() -> CredentialSource | None:
        return await store.get_source(ProviderName.OLLAMA)

    result = asyncio.run(_run())
    assert result is None
