# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for Win32 credential-error typing in the credential store.

``keyring.backends.Windows.WinVaultKeyring`` reaches the Windows Credential
Manager through ``win32ctypes`` (or ``pywin32``) and surfaces every
``CredRead``/``CredWrite``/``CredDelete`` failure as ``pywintypes.error``,
which derives directly from :class:`Exception` -- it is neither an
:class:`OSError` nor a :class:`keyring.errors.KeyringError`. Before those
types were added to the store's ``except`` tuples, a Win32 credential failure
escaped :class:`~intellicrack.credentials.store.CredentialStore` untyped and
bypassed the ``.env`` fallback entirely.

The gate asserts observable store behaviour against the real backend with no
patching, so it fails if the discovered exception tuple stops covering the
type the backend actually raises -- exactly the regression that reintroduces
the defect.

The probe write is isolated under a unique per-test keyring service name, so
the caller's real ``intellicrack`` credentials are never read, written or
deleted.
"""

from __future__ import annotations

import asyncio
import sys
import uuid

import pytest

from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.credentials import store as store_module


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Win32 credential-error typing targets the Windows Credential Manager backend.",
)

_CRED_MAX_BLOB_CHARS = 1280
"""Largest secret WinVaultKeyring stores: CRED_MAX_CREDENTIAL_BLOB_SIZE / 2 (UTF-16)."""

_PROBE_PROVIDER = ProviderName.OLLAMA
"""Provider key used for the probe write; harmless because the service name is isolated."""


@pytest.fixture
def isolated_store(monkeypatch: pytest.MonkeyPatch) -> store_module.CredentialStore:
    """Build a credential store bound to a throwaway keyring service name.

    Args:
        monkeypatch: Pytest monkeypatch fixture, which restores the real
            service name when the test ends.

    Returns:
        store_module.CredentialStore: A store whose writes cannot collide
        with the caller's real ``intellicrack`` credentials.
    """
    service = f"intellicrack-test-{uuid.uuid4().hex}"
    monkeypatch.setattr(store_module.CredentialStore, "SERVICE_NAME", service)
    store = store_module.CredentialStore()
    if not store.keyring_available:
        pytest.skip("Keyring backend is not available on this host.")
    return store


def test_oversized_secret_maps_to_typed_error(isolated_store: store_module.CredentialStore) -> None:
    """An over-cap secret must surface as ``CredentialStoreError``.

    Exercises the genuine Win32 failure with no patching at all: Windows
    Credential Manager rejects a credential blob larger than
    ``CRED_MAX_CREDENTIAL_BLOB_SIZE`` (2560 bytes, i.e. 1280 UTF-16 chars)
    and ``CredWrite`` raises ``WinError 1783`` as a ``pywintypes.error``. The
    store must translate that into its own typed error rather than letting
    the raw Win32 error escape to the caller.

    Args:
        isolated_store: Store bound to a throwaway keyring service name.
    """
    oversized = ProviderCredentials(api_key="x" * (_CRED_MAX_BLOB_CHARS * 2))

    with pytest.raises(store_module.CredentialStoreError):
        asyncio.run(isolated_store.set(_PROBE_PROVIDER, oversized))


def test_within_cap_secret_still_round_trips(isolated_store: store_module.CredentialStore) -> None:
    """A normal-sized key must still store and load, proving the gate is specific.

    Without this companion the over-cap gate could pass for the wrong reason
    (every write failing). A realistic ~200-character API key must survive a
    full round trip through the same isolated store.

    Args:
        isolated_store: Store bound to a throwaway keyring service name.
    """
    secret = f"sk-{uuid.uuid4().hex}-" + ("k" * 160)

    async def _round_trip() -> str | None:
        """Store then reload the probe credential.

        Returns:
            str | None: The API key read back from the keyring.
        """
        await isolated_store.set(_PROBE_PROVIDER, ProviderCredentials(api_key=secret))
        try:
            loaded = await isolated_store.get(_PROBE_PROVIDER)
        finally:
            await isolated_store.delete(_PROBE_PROVIDER)
        return None if loaded is None else loaded.api_key

    assert asyncio.run(_round_trip()) == secret
