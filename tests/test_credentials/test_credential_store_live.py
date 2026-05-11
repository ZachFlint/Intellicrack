# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Live end-to-end tests for the credential store against the real OS keyring.

These tests exercise the real Windows Credential Manager backend where
available. Each test reloads the credential store module via
``importlib.reload`` to reset the module-level singleton between tests
without touching private attributes directly.

The tests verify:

* ``list_providers()`` does not deadlock when the internal ``asyncio.Lock``
  would otherwise be re-entered.
* ``get_credential_store()`` is thread-safe under concurrent access from
  many threads.
* A credential can be round-tripped through the real OS keyring backend.
* Simulated keyring failures raise ``KeyringError`` and are mapped into
  :class:`CredentialStoreError` or :class:`KeyringUnavailableError` as
  appropriate.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import threading
import uuid
from typing import TYPE_CHECKING, Protocol, cast

import pytest

from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.credentials import store as store_module_original


if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import ModuleType


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Live credential store tests target Windows Credential Manager.",
)


class _StoreProtocol(Protocol):
    """Structural protocol for the live :class:`CredentialStore` instance.

    Attributes:
        keyring_available: Whether the live keyring backend is usable.
    """

    keyring_available: bool

    async def get(self, provider: ProviderName) -> ProviderCredentials | None:
        """Retrieve credentials for a provider.

        Args:
            provider: The provider to look up.

        Returns:
            ProviderCredentials | None: Credentials, or ``None`` when unset.
        """
        ...

    async def set(
        self,
        provider: ProviderName,
        credentials: ProviderCredentials,
    ) -> None:
        """Persist credentials for a provider.

        Args:
            provider: The provider to store credentials for.
            credentials: The credentials to persist.
        """
        ...

    async def delete(self, provider: ProviderName) -> bool:
        """Remove credentials for a provider.

        Args:
            provider: The provider whose credentials should be deleted.

        Returns:
            bool: ``True`` if a credential was removed.
        """
        ...

    async def list_providers(self) -> list[object]:
        """List stored credential metadata.

        Returns:
            list[object]: Stored credential metadata entries.
        """
        ...


def _reload_store() -> ModuleType:
    """Reload the credential store module to reset the singleton state.

    Returns:
        ModuleType: The freshly reloaded store module.
    """
    return importlib.reload(store_module_original)


@pytest.fixture
def store_module_fresh() -> Iterator[ModuleType]:
    """Yield a freshly reloaded credential store module.

    Yields:
        ModuleType: The reloaded ``intellicrack.credentials.store`` module.
    """
    yield _reload_store()
    _reload_store()


def _get_store(module: ModuleType) -> _StoreProtocol:
    """Return the singleton credential store from the reloaded module.

    Args:
        module: The credential store module (post-reload).

    Returns:
        _StoreProtocol: A typed view of the live singleton instance.
    """
    factory = module.get_credential_store
    assert callable(factory)
    return cast(_StoreProtocol, factory())


def _credential_store_error(module: ModuleType) -> type[Exception]:
    """Return the ``CredentialStoreError`` class from the reloaded module.

    Args:
        module: The reloaded credential store module.

    Returns:
        type[Exception]: The exception class used by the store.
    """
    error_cls = module.CredentialStoreError
    assert isinstance(error_cls, type)
    assert issubclass(error_cls, Exception)
    return error_cls


def _keyring_backend_usable(module: ModuleType) -> bool:
    """Return True when the active keyring backend can store credentials.

    Args:
        module: The credential store module (post-reload).

    Returns:
        bool: True if the underlying keyring backend is functional.
    """
    return bool(_get_store(module).keyring_available)


def test_list_providers_no_deadlock(store_module_fresh: ModuleType) -> None:
    """``list_providers`` must not deadlock when acquiring the internal lock.

    Previously ``list_providers`` held ``self._lock`` and then called
    ``self.get`` which attempted to re-enter the same ``asyncio.Lock``,
    causing a deadlock.

    Args:
        store_module_fresh: The freshly reloaded credential store module.
    """
    if not _keyring_backend_usable(store_module_fresh):
        pytest.skip("Keyring backend is not available on this host.")

    store = _get_store(store_module_fresh)

    async def _run() -> list[object]:
        return list(await asyncio.wait_for(store.list_providers(), timeout=5.0))

    result = asyncio.run(_run())
    assert isinstance(result, list)


def test_singleton_thread_safe(store_module_fresh: ModuleType) -> None:
    """Concurrent callers must observe a single shared CredentialStore.

    Spawns 32 threads that each retrieve the global credential store and
    asserts that every thread received the same instance id.

    Args:
        store_module_fresh: The freshly reloaded credential store module.
    """
    factory = store_module_fresh.get_credential_store
    assert callable(factory)

    ready = threading.Event()
    collected: list[int] = []
    collected_lock = threading.Lock()

    def _worker() -> None:
        ready.wait()
        instance = factory()
        with collected_lock:
            collected.append(id(instance))

    workers = [threading.Thread(target=_worker) for _ in range(32)]
    for worker in workers:
        worker.start()
    ready.set()
    for worker in workers:
        worker.join(timeout=10.0)
        assert not worker.is_alive(), "Worker thread did not complete in time."

    assert len(collected) == 32
    assert len(set(collected)) == 1, f"Expected one singleton id, got {set(collected)}"


def test_credential_roundtrip_live(store_module_fresh: ModuleType) -> None:
    """Round-trip a synthetic credential through the real OS keyring.

    Args:
        store_module_fresh: The freshly reloaded credential store module.
    """
    if not _keyring_backend_usable(store_module_fresh):
        pytest.skip("Keyring backend is not available on this host.")

    store = _get_store(store_module_fresh)
    provider = ProviderName.OLLAMA
    marker = f"live-marker-{uuid.uuid4().hex}"
    creds = ProviderCredentials(
        api_key=marker,
        api_base=None,
        organization_id=None,
        project_id=None,
    )

    async def _run() -> tuple[ProviderCredentials | None, bool]:
        await store.set(provider, creds)
        try:
            fetched = await store.get(provider)
        finally:
            deleted = await store.delete(provider)
        return fetched, deleted

    fetched, deleted = asyncio.run(_run())
    assert fetched is not None
    assert fetched.api_key == marker
    assert deleted is True


def test_keyring_error_handled(
    store_module_fresh: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulated keyring failures must raise ``CredentialStoreError``.

    Monkeypatches ``keyring.set_password`` on the loaded keyring module to
    raise :class:`keyring.errors.InitError` and asserts the store maps it
    to the module-level ``CredentialStoreError`` instead of leaking the
    raw keyring-layer error.

    Args:
        store_module_fresh: The freshly reloaded credential store module.
        monkeypatch: Pytest monkeypatch fixture.
    """
    if not _keyring_backend_usable(store_module_fresh):
        pytest.skip("Keyring backend is not available on this host.")

    import keyring
    import keyring.errors

    def _raise(*_args: object, **_kwargs: object) -> None:
        msg = "simulated backend failure"
        raise keyring.errors.InitError(msg)

    monkeypatch.setattr(keyring, "set_password", _raise)

    store = _get_store(store_module_fresh)
    provider = ProviderName.OLLAMA
    placeholder_value = f"placeholder-{uuid.uuid4().hex}"
    creds = ProviderCredentials(
        api_key=placeholder_value,
        api_base=None,
        organization_id=None,
        project_id=None,
    )

    async def _run() -> None:
        await store.set(provider, creds)

    with pytest.raises(_credential_store_error(store_module_fresh)):
        asyncio.run(_run())
