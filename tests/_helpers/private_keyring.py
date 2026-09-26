# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real file-backed keyrings confined to a test's own directory.

The suite's configured backend is ``keyrings.alt``'s plaintext file keyring, which normally writes to one file shared by every test and
every xdist worker. These helpers give a test its own file, install it as the process keyring for the test's duration, and restore the
previous backend afterwards. Nothing is simulated: reads and writes go through the real backend to a real file.
"""

from __future__ import annotations

import string
from contextlib import contextmanager
from typing import TYPE_CHECKING, Protocol, cast

import keyring
import keyring.core
from keyring.backend import KeyringBackend
from keyring.compat import properties
from keyring.errors import PasswordSetError


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


PLAINTEXT_FILE_KEYRING = "keyrings.alt.file.PlaintextKeyring"
"""The file-backed keyring the suite is configured with."""

CRED_MAX_CREDENTIAL_BLOB_SIZE = 5 * 512
"""Windows ``CRED_MAX_CREDENTIAL_BLOB_SIZE``: the largest generic credential blob ``CredWrite`` accepts."""


def private_file_keyring(path: Path) -> KeyringBackend:
    """Build the plaintext file keyring over a private file.

    Args:
        path: The keyring file to use.

    Returns:
        KeyringBackend: The backend.
    """
    backend = keyring.core.load_keyring(PLAINTEXT_FILE_KEYRING)
    vars(backend)["file_path"] = str(path)
    return backend


def file_keyring_entry_name(value: str) -> str:
    """Render a service or entry name the way the file keyring writes it to disk.

    ``keyrings.alt`` keeps ASCII letters and digits and writes every other
    UTF-8 byte as ``_XX``; a test that edits the file directly needs the same
    rendering to find an entry.

    Args:
        value: The service or entry name.

    Returns:
        str: The name as it appears in the keyring file.
    """
    legal = string.ascii_letters + string.digits
    return "".join(chr(byte) if chr(byte) in legal else f"_{byte:02X}" for byte in value.encode("utf-8"))


class SecretBackend(Protocol):
    """The three calls a keyring backend answers."""

    def get_password(self, service: str, username: str) -> str | None:
        """Read a secret.

        Args:
            service: The service name.
            username: The entry name.

        Returns:
            str | None: The secret, or ``None`` when absent.
        """
        ...

    def set_password(self, service: str, username: str, password: str) -> None:
        """Store a secret.

        Args:
            service: The service name.
            username: The entry name.
            password: The secret.
        """

    def delete_password(self, service: str, username: str) -> None:
        """Delete a secret.

        Args:
            service: The service name.
            username: The entry name.
        """


class CredentialManagerSizedKeyring(KeyringBackend):
    """A real keyring that refuses what Windows Credential Manager refuses.

    Storage is delegated to a real backend. Like ``CredWrite``, a secret whose UTF-16 encoding exceeds ``CRED_MAX_CREDENTIAL_BLOB_SIZE`` is
    refused with :class:`keyring.errors.PasswordSetError`, so code that stores large secrets is exercised against the limit it has to
    respect on Windows.
    """

    def __init__(self, path: Path) -> None:
        """Store for real in a private file keyring.

        Args:
            path: The keyring file.
        """
        super().__init__()
        self._inner = cast("SecretBackend", private_file_keyring(path))

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
        """Store a secret unless it is over the Credential Manager blob limit.

        Args:
            service: The service name.
            username: The entry name.
            password: The secret.

        Raises:
            PasswordSetError: If the UTF-16 blob is over the limit.
        """
        size = len(password.encode("utf-16-le"))
        if size > CRED_MAX_CREDENTIAL_BLOB_SIZE:
            message = f"CredWrite: a {size}-byte blob exceeds CRED_MAX_CREDENTIAL_BLOB_SIZE ({CRED_MAX_CREDENTIAL_BLOB_SIZE})"
            raise PasswordSetError(message)
        self._inner.set_password(service, username, password)

    def delete_password(self, service: str, username: str) -> None:
        """Delete a secret.

        Args:
            service: The service name.
            username: The entry name.
        """
        self._inner.delete_password(service, username)


@contextmanager
def installed_keyring(backend: KeyringBackend) -> Generator[KeyringBackend]:
    """Make ``backend`` the process keyring until the block exits.

    Args:
        backend: The backend to install.

    Yields:
        KeyringBackend: The installed backend.
    """
    previous = keyring.get_keyring()
    keyring.set_keyring(backend)
    try:
        yield backend
    finally:
        keyring.set_keyring(previous)
