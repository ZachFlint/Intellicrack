# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for previously untested credential-store entry points.

These tests exercise the public surface of
:mod:`intellicrack.credentials.store` against the real OS keyring backend
(Windows Credential Manager on the CI host and inside the Windows Docker
container) and against real on-disk ``.env`` files.

The following capabilities, previously without any test, are covered here:

* The module-level async wrapper :func:`get_credentials`.
* :meth:`CredentialStore.migrate_from_env` (env -> keyring copy semantics,
  including the ``overwrite=False`` skip path).
* :meth:`CredentialStore.validate` per-provider API-key format rules.
* :meth:`CredentialStore.get_source` for both the keyring and env paths.

Every credential value used as a marker is generated per test with
``uuid.uuid4().hex`` so concurrent runs never collide, and each test deletes
its keyring entries on teardown to keep the developer's credential store
clean.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from typing import TYPE_CHECKING

import keyring
import keyring.errors
import pytest

from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import (
    CredentialSource,
    CredentialStore,
    get_credential_store,
    get_credentials,
)


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Live credential store tests target Windows Credential Manager.",
)

_SERVICE_NAME = "intellicrack"


def _keyring_usable() -> bool:
    """Return True when a real (non fail/null) keyring backend is active.

    Returns:
        bool: True if credentials can round-trip through the OS keyring.
    """
    return bool(CredentialStore().keyring_available)


def _purge(provider: ProviderName) -> None:
    """Delete any keyring entries left behind for a provider.

    Args:
        provider: The provider whose keyring keys should be removed.
    """
    key = f"{_SERVICE_NAME}_{provider.value}"
    for name in (key, f"{key}_metadata"):
        try:
            keyring.delete_password(_SERVICE_NAME, name)
        except keyring.errors.PasswordDeleteError:
            pass
        except keyring.errors.KeyringError:
            pass


@pytest.fixture
def ollama_clean() -> Iterator[ProviderName]:
    """Yield the OLLAMA provider with keyring entries purged before/after.

    Yields:
        ProviderName: The OLLAMA provider name.
    """
    _purge(ProviderName.OLLAMA)
    yield ProviderName.OLLAMA
    _purge(ProviderName.OLLAMA)


@pytest.fixture
def anthropic_clean() -> Iterator[ProviderName]:
    """Yield the ANTHROPIC provider with keyring entries purged before/after.

    Yields:
        ProviderName: The ANTHROPIC provider name.
    """
    _purge(ProviderName.ANTHROPIC)
    yield ProviderName.ANTHROPIC
    _purge(ProviderName.ANTHROPIC)


@pytest.fixture
def restore_env() -> Iterator[None]:
    """Snapshot and restore ``os.environ`` around tests that load ``.env`` files.

    :class:`CredentialLoader` writes parsed ``.env`` variables into
    ``os.environ`` for cross-library compatibility; this fixture guarantees
    that mutation does not leak into sibling tests.

    Yields:
        None: Nothing; restores the process environment on teardown.
    """
    snapshot = dict(os.environ)
    yield
    for key in set(os.environ) - set(snapshot):
        del os.environ[key]
    for key, value in snapshot.items():
        os.environ[key] = value


def _write_env(path: Path, **values: str) -> Path:
    """Write a ``.env`` file under ``path`` with the supplied variables.

    Args:
        path: Directory in which to write the ``.env`` file.
        **values: Mapping of env-var names to values.

    Returns:
        Path: The absolute path to the written ``.env`` file.
    """
    env_file = path / ".env"
    lines = [f"{name}={value}" for name, value in values.items()]
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return env_file


def test_get_credentials_wrapper_returns_seeded_value(ollama_clean: ProviderName) -> None:
    """The module-level :func:`get_credentials` returns what the store holds.

    Seeds a credential through ``get_credential_store().set`` (real keyring
    write) and then reads it back through the standalone async wrapper,
    asserting the wrapper delegates to the same singleton store.

    Args:
        ollama_clean: Purged OLLAMA provider name.
    """
    if not _keyring_usable():
        pytest.skip("Keyring backend is not available on this host.")

    marker = f"wrapper-{uuid.uuid4().hex}"
    creds = ProviderCredentials(api_key=marker, api_base=None, organization_id=None, project_id=None)

    async def _run() -> ProviderCredentials | None:
        await get_credential_store().set(ollama_clean, creds)
        return await get_credentials(ollama_clean)

    fetched = asyncio.run(_run())
    assert fetched is not None
    assert fetched.api_key == marker


def test_get_credentials_wrapper_delegates_to_singleton(ollama_clean: ProviderName) -> None:
    """:func:`get_credentials` returns exactly what the singleton store yields.

    Rather than asserting ``None`` (the ambient environment may carry a real
    ``OLLAMA`` credential on a developer host), this proves the standalone
    wrapper delegates to :func:`get_credential_store` and never raises: the
    wrapper result must equal the singleton's own ``get`` result for the same
    provider.

    Args:
        ollama_clean: Purged OLLAMA provider name.
    """
    if not _keyring_usable():
        pytest.skip("Keyring backend is not available on this host.")

    async def _run() -> tuple[ProviderCredentials | None, ProviderCredentials | None]:
        via_wrapper = await get_credentials(ollama_clean)
        via_store = await get_credential_store().get(ollama_clean)
        return via_wrapper, via_store

    wrapper_result, store_result = asyncio.run(_run())
    assert wrapper_result == store_result


def test_migrate_from_env_copies_into_keyring(
    tmp_path: Path,
    ollama_clean: ProviderName,
    restore_env: None,
) -> None:
    """``migrate_from_env`` copies an env credential into the OS keyring.

    Args:
        tmp_path: Pytest temporary directory holding the ``.env`` file.
        ollama_clean: Purged OLLAMA provider name.
        restore_env: Fixture restoring ``os.environ`` on teardown.
    """
    del restore_env
    if not _keyring_usable():
        pytest.skip("Keyring backend is not available on this host.")

    marker = f"migrate-{uuid.uuid4().hex}"
    env_file = _write_env(tmp_path, OLLAMA_API_KEY=marker)
    store = CredentialStore(fallback_loader=CredentialLoader(env_path=env_file))

    async def _run() -> dict[ProviderName, bool]:
        return await store.migrate_from_env([ollama_clean])

    result = asyncio.run(_run())
    assert result[ollama_clean] is True

    stored = keyring.get_password(_SERVICE_NAME, f"{_SERVICE_NAME}_{ollama_clean.value}")
    assert stored is not None
    assert marker in stored


def test_migrate_from_env_overwrite_false_skips_existing(
    tmp_path: Path,
    ollama_clean: ProviderName,
    restore_env: None,
) -> None:
    """With ``overwrite=False`` an already-present keyring entry is preserved.

    Args:
        tmp_path: Pytest temporary directory holding the ``.env`` file.
        ollama_clean: Purged OLLAMA provider name.
        restore_env: Fixture restoring ``os.environ`` on teardown.
    """
    del restore_env
    if not _keyring_usable():
        pytest.skip("Keyring backend is not available on this host.")

    keyring_marker = f"already-{uuid.uuid4().hex}"
    env_marker = f"fromenv-{uuid.uuid4().hex}"
    existing = ProviderCredentials(api_key=keyring_marker, api_base=None, organization_id=None, project_id=None)

    env_file = _write_env(tmp_path, OLLAMA_API_KEY=env_marker)
    store = CredentialStore(fallback_loader=CredentialLoader(env_path=env_file))

    async def _run() -> tuple[dict[ProviderName, bool], ProviderCredentials | None]:
        await store.set(ollama_clean, existing)
        migrated = await store.migrate_from_env([ollama_clean], overwrite=False)
        after = await store.get(ollama_clean)
        return migrated, after

    result, after = asyncio.run(_run())
    assert result[ollama_clean] is True
    assert after is not None
    assert after.api_key == keyring_marker


def test_migrate_from_env_overwrite_true_replaces(
    tmp_path: Path,
    ollama_clean: ProviderName,
    restore_env: None,
) -> None:
    """With ``overwrite=True`` the env value replaces the keyring entry.

    Args:
        tmp_path: Pytest temporary directory holding the ``.env`` file.
        ollama_clean: Purged OLLAMA provider name.
        restore_env: Fixture restoring ``os.environ`` on teardown.
    """
    del restore_env
    if not _keyring_usable():
        pytest.skip("Keyring backend is not available on this host.")

    keyring_marker = f"old-{uuid.uuid4().hex}"
    env_marker = f"new-{uuid.uuid4().hex}"
    existing = ProviderCredentials(api_key=keyring_marker, api_base=None, organization_id=None, project_id=None)

    env_file = _write_env(tmp_path, OLLAMA_API_KEY=env_marker)
    store = CredentialStore(fallback_loader=CredentialLoader(env_path=env_file))

    async def _run() -> ProviderCredentials | None:
        await store.set(ollama_clean, existing)
        await store.migrate_from_env([ollama_clean], overwrite=True)
        return await store.get(ollama_clean)

    after = asyncio.run(_run())
    assert after is not None
    assert after.api_key == env_marker


def test_validate_accepts_correct_anthropic_prefix(anthropic_clean: ProviderName) -> None:
    """``validate`` accepts an Anthropic key with the ``sk-ant-`` prefix.

    Args:
        anthropic_clean: Purged ANTHROPIC provider name.
    """
    if not _keyring_usable():
        pytest.skip("Keyring backend is not available on this host.")

    store = CredentialStore()
    creds = ProviderCredentials(
        api_key=f"sk-ant-{uuid.uuid4().hex}",
        api_base=None,
        organization_id=None,
        project_id=None,
    )

    async def _run() -> tuple[bool, str | None]:
        await store.set(anthropic_clean, creds)
        return await store.validate(anthropic_clean)

    valid, error = asyncio.run(_run())
    assert valid is True
    assert error is None


def test_validate_rejects_wrong_anthropic_prefix(anthropic_clean: ProviderName) -> None:
    """``validate`` rejects an Anthropic key missing the ``sk-ant-`` prefix.

    Args:
        anthropic_clean: Purged ANTHROPIC provider name.
    """
    if not _keyring_usable():
        pytest.skip("Keyring backend is not available on this host.")

    store = CredentialStore()
    creds = ProviderCredentials(
        api_key=f"sk-openai-{uuid.uuid4().hex}",
        api_base=None,
        organization_id=None,
        project_id=None,
    )

    async def _run() -> tuple[bool, str | None]:
        await store.set(anthropic_clean, creds)
        return await store.validate(anthropic_clean)

    valid, error = asyncio.run(_run())
    assert valid is False
    assert error is not None
    assert error


@pytest.mark.parametrize(
    ("provider", "good_key", "bad_key"),
    [
        (ProviderName.OPENAI, "sk-", "xx-"),
        (ProviderName.ANTHROPIC, "sk-ant-", "sk-"),
        (ProviderName.GOOGLE, "AIza", "BBza"),
        (ProviderName.GROK, "xai-", "grok-"),
        (ProviderName.HUGGINGFACE, "hf_", "xf_"),
        (ProviderName.OPENROUTER, "sk-or-", "sk-"),
    ],
)
def test_validate_per_provider_prefix_branches(
    provider: ProviderName,
    good_key: str,
    bad_key: str,
) -> None:
    """Each per-provider prefix branch accepts a valid key and rejects a bad one.

    Args:
        provider: Provider whose validate branch is exercised.
        good_key: Prefix that should validate as correct.
        bad_key: Prefix that should be rejected.
    """
    if not _keyring_usable():
        pytest.skip("Keyring backend is not available on this host.")

    store = CredentialStore()
    suffix = uuid.uuid4().hex
    good = ProviderCredentials(api_key=f"{good_key}{suffix}", api_base=None, organization_id=None, project_id=None)
    bad = ProviderCredentials(api_key=f"{bad_key}{suffix}", api_base=None, organization_id=None, project_id=None)

    async def _run() -> tuple[tuple[bool, str | None], tuple[bool, str | None]]:
        try:
            await store.set(provider, good)
            ok = await store.validate(provider)
            await store.set(provider, bad)
            rejected = await store.validate(provider)
        finally:
            await store.delete(provider)
        return ok, rejected

    (ok_valid, ok_error), (bad_valid, bad_error) = asyncio.run(_run())
    assert ok_valid is True, f"{provider.value} good key was rejected: {ok_error}"
    assert ok_error is None
    assert bad_valid is False, f"{provider.value} bad key was accepted"
    assert bad_error


def test_get_source_returns_keyring_for_stored_credential(ollama_clean: ProviderName) -> None:
    """``get_source`` reports ``KEYRING`` for a credential stored via ``set``.

    Args:
        ollama_clean: Purged OLLAMA provider name.
    """
    if not _keyring_usable():
        pytest.skip("Keyring backend is not available on this host.")

    store = CredentialStore()
    creds = ProviderCredentials(
        api_key=f"src-{uuid.uuid4().hex}",
        api_base=None,
        organization_id=None,
        project_id=None,
    )

    async def _run() -> CredentialSource | None:
        await store.set(ollama_clean, creds)
        return await store.get_source(ollama_clean)

    source = asyncio.run(_run())
    assert source is not None
    assert source.value == CredentialSource.KEYRING.value


def test_get_source_returns_env_file_for_env_only_credential(
    tmp_path: Path,
    ollama_clean: ProviderName,
    restore_env: None,
) -> None:
    """``get_source`` reports an env source when only a ``.env`` credential exists.

    The env-var name OLLAMA_HOST is intentionally omitted so the loader
    surfaces only an api-key from the ``.env`` file, exercising the env
    fallback branch of ``get_source``.

    Args:
        tmp_path: Pytest temporary directory holding the ``.env`` file.
        ollama_clean: Purged OLLAMA provider name (no keyring entry).
        restore_env: Fixture restoring ``os.environ`` on teardown.
    """
    del restore_env
    if not _keyring_usable():
        pytest.skip("Keyring backend is not available on this host.")

    marker = f"envsrc-{uuid.uuid4().hex}"
    env_file = _write_env(tmp_path, OLLAMA_API_KEY=marker)
    store = CredentialStore(fallback_loader=CredentialLoader(env_path=env_file))

    async def _run() -> CredentialSource | None:
        return await store.get_source(ollama_clean)

    source = asyncio.run(_run())
    assert source is not None
    assert source.value in {CredentialSource.ENV_FILE.value, CredentialSource.ENV_VAR.value}
