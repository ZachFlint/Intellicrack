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

No test here touches the operating system's own keyring. The store runs over
a real file-backed keyring in the test's own directory, sized like Credential
Manager (:class:`~tests._helpers.private_keyring.CredentialManagerSizedKeyring`),
whose writes additionally refuse an over-long entry name the way ``CredWrite``
does: by raising the genuine ``win32ctypes`` ``pywintypes.error`` that
``WinVaultKeyring`` lets escape. The gate then asserts the store translates
exactly that error, so it fails if the store's exception tuple stops covering
the type the Windows backend raises -- the regression that reintroduces the
defect.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import uuid
from typing import TYPE_CHECKING, Final, cast

import pytest
from keyring.backend import KeyringBackend
from keyring.compat import properties

from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials import store as store_module
from intellicrack.providers import ids as provider_ids
from tests._helpers.private_keyring import CredentialManagerSizedKeyring, installed_keyring


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from tests._helpers.private_keyring import SecretBackend


_CRED_MAX_USERNAME_LENGTH: Final[int] = 513
"""Longest ``UserName`` Credential Manager accepts for a credential (``CRED_MAX_USERNAME_LENGTH``)."""

_ERROR_INVALID_PARAMETER: Final[int] = 87
"""Win32 ``ERROR_INVALID_PARAMETER``, which ``CredWrite`` returns for a field over its documented maximum."""

_ERROR_INVALID_PARAMETER_TEXT: Final[str] = "The parameter is incorrect."
"""The system message for ``ERROR_INVALID_PARAMETER``."""

_PROBE_PROVIDER = provider_ids.OLLAMA
"""Provider key used for the probe write; harmless because the keyring is private to the test."""


_PYWINTYPES_MODULE: Final[str] = "win32ctypes.pywin32.pywintypes"
"""The pywin32 shim module ``keyring``'s Windows backend prefers, whose ``error`` a Credential Manager failure escapes as."""


def _win32_credential_error_type() -> type[Exception]:
    """Return the ``pywintypes.error`` class ``WinVaultKeyring`` raises.

    Returns:
        type[Exception]: The ``win32ctypes.pywin32.pywintypes.error`` class.
    """
    error_type: object = getattr(importlib.import_module(_PYWINTYPES_MODULE), "error")
    assert isinstance(error_type, type), "win32ctypes.pywin32.pywintypes.error must be a class"
    assert issubclass(error_type, Exception), "win32ctypes.pywin32.pywintypes.error must be an exception"
    return error_type


class _CredWriteRefusingKeyring(KeyringBackend):
    """A private, Credential-Manager-sized keyring that also refuses an over-long entry name as ``CredWrite`` does.

    Storage goes to a real :class:`CredentialManagerSizedKeyring` over a private
    file, which already refuses an over-cap blob. ``WinVaultKeyring`` writes the
    keyring entry name as the credential's ``UserName``, and ``CredWrite``
    refuses one longer than ``CRED_MAX_USERNAME_LENGTH`` with
    ``ERROR_INVALID_PARAMETER``, which reaches the caller as
    ``pywintypes.error``; this keyring raises that same error for such a write.
    """

    def __init__(self, path: Path) -> None:
        """Store for real in a private, Credential-Manager-sized file keyring.

        Args:
            path: The keyring file.
        """
        super().__init__()
        self._inner = cast("SecretBackend", CredentialManagerSizedKeyring(path))

    @properties.classproperty
    def priority(self) -> float:
        """Rank above the fallback backends.

        Returns:
            float: The backend priority.
        """
        del self
        return 1.0

    def get_password(self, service: str, username: str) -> str | None:
        """Read a secret.

        Args:
            service: The service name.
            username: The entry name.

        Returns:
            str | None: The secret, or ``None`` when absent.
        """
        return self._inner.get_password(service, username)

    def set_password(self, service: str, username: str, password: str) -> None:
        """Store a secret unless Credential Manager would refuse it.

        Args:
            service: The service name.
            username: The entry name, written as the credential's ``UserName``.
            password: The secret.

        Raises:
            pywintypes.error: ``ERROR_INVALID_PARAMETER`` from ``CredWrite``
                for an entry name over ``CRED_MAX_USERNAME_LENGTH``.
        """
        if len(username) > _CRED_MAX_USERNAME_LENGTH:
            pywintypes = importlib.import_module(_PYWINTYPES_MODULE)
            raise pywintypes.error(_ERROR_INVALID_PARAMETER, "CredWrite", _ERROR_INVALID_PARAMETER_TEXT)
        self._inner.set_password(service, username, password)

    def delete_password(self, service: str, username: str) -> None:
        """Delete a secret.

        Args:
            service: The service name.
            username: The entry name.
        """
        self._inner.delete_password(service, username)


def _store_over(backend: KeyringBackend, monkeypatch: pytest.MonkeyPatch) -> Iterator[store_module.CredentialStore]:
    """Install ``backend`` as the process keyring and build a store over it.

    Args:
        backend: The private backend to install.
        monkeypatch: Restores the store's service name after the test.

    Yields:
        store_module.CredentialStore: A store whose reads and writes reach only ``backend``.
    """
    monkeypatch.setattr(store_module.CredentialStore, "SERVICE_NAME", f"intellicrack-test-{uuid.uuid4().hex}")
    with installed_keyring(backend):
        store = store_module.CredentialStore()
        assert store.keyring_available, "the private keyring was not picked up by the store"
        yield store


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Mapping a Win32 credential error: win32ctypes' pywintypes.error, the type WinVaultKeyring raises, exists only on Windows.",
)
def test_win32_credential_error_maps_to_typed_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``pywintypes.error`` from the keyring must surface as ``CredentialStoreError``.

    The store files a provider under an entry name longer than
    ``CRED_MAX_USERNAME_LENGTH``; the keyring refuses the write with the
    ``pywintypes.error`` ``CredWrite`` raises, and the store must translate
    that into its own typed error -- not the "keyring is full" error, since
    this is no quota failure -- with the Win32 error as its cause, rather than
    letting the raw error escape. Nothing may be stored by the refused write,
    and a normal entry written through the same keyring must still succeed, so
    the gate cannot pass because every write fails.

    Args:
        tmp_path: Per-test directory holding the private keyring file.
        monkeypatch: Restores the store's service name after the test.
    """
    backend = _CredWriteRefusingKeyring(tmp_path / "keyring_pass.cfg")
    over_long_provider = "p" * (_CRED_MAX_USERNAME_LENGTH + 1)
    secret = f"sk-{uuid.uuid4().hex}"

    for store in _store_over(backend, monkeypatch):
        with pytest.raises(store_module.CredentialStoreError) as caught:
            asyncio.run(store.set(over_long_provider, ProviderCredentials(api_key="sk-probe")))

        cause = caught.value.__cause__
        assert not isinstance(caught.value, store_module.CredentialStoreFullError)
        assert type(cause) is _win32_credential_error_type(), f"the typed error was not raised from the Win32 refusal: {cause!r}"
        assert getattr(cause, "winerror", None) == _ERROR_INVALID_PARAMETER
        assert getattr(cause, "funcname", None) == "CredWrite"
        assert backend.get_password(store.SERVICE_NAME, f"{store.SERVICE_NAME}_{over_long_provider}") is None

        asyncio.run(store.set(_PROBE_PROVIDER, ProviderCredentials(api_key=secret)))
        loaded = asyncio.run(store.get_secret(_PROBE_PROVIDER))
        assert loaded is not None
        assert loaded.api_key == secret


def test_within_cap_secret_still_round_trips(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A normal-sized key must still store and load through a Credential-Manager-sized keyring.

    A realistic ~200-character API key fits one Credential Manager blob, so the
    store writes it as a single entry the sized keyring accepts; it must survive
    a full round trip and be gone after deletion.

    Args:
        tmp_path: Per-test directory holding the private keyring file.
        monkeypatch: Restores the store's service name after the test.
    """
    secret = f"sk-{uuid.uuid4().hex}-" + ("k" * 160)

    async def _round_trip(store: store_module.CredentialStore) -> tuple[str | None, ProviderCredentials | None]:
        """Store, reload, then delete the probe credential.

        Args:
            store: The store under test.

        Returns:
            tuple[str | None, ProviderCredentials | None]: The API key read back
            and what a read finds after deletion.
        """
        await store.set(_PROBE_PROVIDER, ProviderCredentials(api_key=secret))
        try:
            loaded = await store.get_secret(_PROBE_PROVIDER)
        finally:
            _ = await store.delete(_PROBE_PROVIDER)
        after = await store.get_secret(_PROBE_PROVIDER)
        return (None if loaded is None else loaded.api_key), after

    for store in _store_over(CredentialManagerSizedKeyring(tmp_path / "keyring_pass.cfg"), monkeypatch):
        loaded, after = asyncio.run(_round_trip(store))
        assert loaded == secret
        assert after is None
