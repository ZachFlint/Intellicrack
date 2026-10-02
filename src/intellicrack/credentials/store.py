# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Secure credential storage using OS keyring.

This module provides secure credential storage using the operating system's native credential manager (Windows Credential Manager, macOS
Keychain, or Linux Secret Service via the keyring library).
"""

from __future__ import annotations

import asyncio
import errno
import json
import secrets
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from functools import cached_property
from typing import TYPE_CHECKING, ClassVar, Final, TypeGuard, cast

from intellicrack.core.logging import get_logger
from intellicrack.core.types import IntellicrackError, ProviderCredentials
from intellicrack.credentials.env_loader import CredentialLoader, get_credential_loader, known_provider_ids, validate_key_format


if TYPE_CHECKING:
    from types import ModuleType

_logger = get_logger(__name__)

try:
    import keyring as _keyring_module
    import keyring.errors as _keyring_errors_module
except ImportError:
    _logger.debug("keyring_import_failed", exc_info=True)
    _keyring_module = None
    _keyring_errors_module = None


class _KeyringFallbackError(Exception):
    """Sentinel exception used when keyring.errors is unavailable.

    This class is never raised. It exists only to provide a concrete exception type for the ``except`` tuples when the optional ``keyring``
    dependency is missing, keeping the code paths type-consistent.
    """


if _keyring_errors_module is not None:
    _KeyringError: type[Exception] = _keyring_errors_module.KeyringError
else:
    _KeyringError = _KeyringFallbackError


try:
    from win32ctypes.pywin32.pywintypes import error as _win32_credential_error
except ImportError:
    _logger.debug("win32_credential_error_unavailable")
    _win32_credential_error = None


class _Win32CredentialFallbackError(Exception):
    """Sentinel exception used when the Win32 credential shim is unavailable.

    This class is never raised. It exists only to keep the ``except`` tuples type-consistent on platforms where ``win32ctypes`` is not
    installed, mirroring :class:`_KeyringFallbackError`.
    """


if _win32_credential_error is not None:
    _Win32CredentialError: type[Exception] = _win32_credential_error
else:
    _Win32CredentialError = _Win32CredentialFallbackError


class CredentialStoreError(IntellicrackError):
    """Base error for credential store operations."""


class KeyringUnavailableError(CredentialStoreError):
    """Keyring backend is not available."""


class CredentialNotFoundError(CredentialStoreError):
    """Requested credential was not found."""


class CredentialStoreFullError(CredentialStoreError):
    """The keyring refused a write because it has no room left.

    Raised in place of the backend's own error so the operator is told what to do about it. Whatever was stored before under the same
    name is still there, unchanged.
    """


class KeyringReadError(CredentialStoreError):
    """The keyring holds an entry for the credential but it could not be read.

    Raised instead of reporting the credential as absent, so a caller never tells the operator to re-enter a secret that is in fact stored.
    """


CRED_MAX_CREDENTIAL_BLOB_BYTES: Final[int] = 5 * 512
"""Largest credential blob Windows Credential Manager accepts (``CRED_MAX_CREDENTIAL_BLOB_SIZE``).

The keyring Windows backend writes every secret as UTF-16, so the limit is measured on the UTF-16 encoding, which puts it at about 1280
characters.
"""

_CHUNK_MANIFEST_MARKER: Final[str] = "intellicrack_chunked_credential"
_CHUNK_MANIFEST_VERSION: Final[int] = 1
_CHUNK_KEY_INFIX: Final[str] = "__chunk_"
_CHUNK_GENERATION_BYTES: Final[int] = 4
_CHUNK_PENDING_SUFFIX: Final[str] = "pending"
_READ_ATTEMPTS: Final[int] = 2

_KEYRING_LOCK: Final[threading.RLock] = threading.RLock()
"""Held for every keyring read, write and delete any :class:`CredentialStore` makes.

A chunked value spans several entries. Two stores writing the same credential, each deleting the chunks it believed were the previous
ones, would orphan each other's; a reader between a writer's manifest switch and its cleanup would find chunks missing. One lock across
every instance in the process makes each read, write and delete of a value atomic with respect to the others.
"""

_WINDOWS_QUOTA_ERRORS: Final[frozenset[int]] = frozenset({8, 14, 112, 1816})
"""``ERROR_NOT_ENOUGH_MEMORY``, ``ERROR_OUTOFMEMORY``, ``ERROR_DISK_FULL`` and ``ERROR_NOT_ENOUGH_QUOTA``: the keyring has no room."""

_POSIX_QUOTA_ERRORS: Final[frozenset[int]] = frozenset({errno.ENOSPC, errno.EDQUOT})
_UTF16_UNIT_BYTES: Final[int] = 2
_UTF16_PAIR_BYTES: Final[int] = 4
_BMP_MAX_CODE_POINT: Final[int] = 0xFFFF


@dataclass(frozen=True, slots=True)
class ChunkManifest:
    """Pointer record stored in place of a credential too large for one keyring entry.

    Attributes:
        generation: Random tag shared by every chunk written together, so a rewrite never mixes chunks from two writes.
        count: Number of chunks the value was split into.
        length: Number of characters in the whole value, checked after reassembly. Nothing derived from the secret's content is
            stored, so the manifest reveals no more than its size.
    """

    generation: str
    count: int
    length: int

    def serialize(self) -> str:
        """Render the manifest as the JSON stored under the credential's own key.

        Returns:
            str: The manifest JSON.
        """
        return json.dumps({
            _CHUNK_MANIFEST_MARKER: _CHUNK_MANIFEST_VERSION,
            "generation": self.generation,
            "count": self.count,
            "length": self.length,
        })

    @staticmethod
    def parse(stored: str) -> ChunkManifest | None:
        """Recognise a stored entry as a chunk manifest.

        Args:
            stored: The value read from the credential's own key.

        Returns:
            ChunkManifest | None: The manifest, or ``None`` when the entry is an ordinary single-entry value.
        """
        if _CHUNK_MANIFEST_MARKER not in stored:
            return None
        try:
            decoded: object = json.loads(stored)
        except json.JSONDecodeError:
            return None
        if not isinstance(decoded, dict):
            return None
        fields = cast("dict[str, object]", decoded)
        if fields.get(_CHUNK_MANIFEST_MARKER) != _CHUNK_MANIFEST_VERSION:
            return None
        generation = fields.get("generation")
        count = fields.get("count")
        length = fields.get("length")
        if not isinstance(generation, str) or not _is_count(count) or not _is_count(length):
            return None
        return ChunkManifest(generation=generation, count=count, length=length)

    def chunk_key(self, key: str, index: int) -> str:
        """Name the keyring entry one chunk is held under.

        Args:
            key: The credential's own keyring key.
            index: Zero-based chunk position.

        Returns:
            str: The chunk's keyring key.
        """
        return f"{key}{_CHUNK_KEY_INFIX}{self.generation}_{index}"


def _pending_key(key: str) -> str:
    """Name the entry recording the chunk generation a write of ``key`` is in the middle of.

    Args:
        key: The value's own keyring key.

    Returns:
        str: The pending marker's keyring key.
    """
    return f"{key}{_CHUNK_KEY_INFIX}{_CHUNK_PENDING_SUFFIX}"


def credential_blob_size(value: str) -> int:
    """Measure a value the way Windows Credential Manager does.

    Args:
        value: The secret as the keyring backend receives it.

    Returns:
        int: Its size in bytes once encoded as UTF-16.
    """
    return sum(_UTF16_PAIR_BYTES if ord(char) > _BMP_MAX_CODE_POINT else _UTF16_UNIT_BYTES for char in value)


def split_credential_blob(value: str, max_bytes: int = CRED_MAX_CREDENTIAL_BLOB_BYTES) -> list[str]:
    """Split a value into pieces that each fit one keyring entry.

    Pieces are cut on code-point boundaries, so a surrogate pair is never divided between two entries.

    Args:
        value: The value to split.
        max_bytes: Largest UTF-16 size one piece may have.

    Returns:
        list[str]: The pieces, in order. Joining them reproduces ``value``.

    Raises:
        ValueError: If ``max_bytes`` cannot hold even one character.
    """
    if max_bytes < _UTF16_PAIR_BYTES:
        message = f"a chunk of {max_bytes} bytes cannot hold a UTF-16 character"
        raise ValueError(message)
    pieces: list[str] = []
    current: list[str] = []
    used = 0
    for char in value:
        size = _UTF16_PAIR_BYTES if ord(char) > _BMP_MAX_CODE_POINT else _UTF16_UNIT_BYTES
        if used + size > max_bytes:
            pieces.append("".join(current))
            current = []
            used = 0
        current.append(char)
        used += size
    if current or not pieces:
        pieces.append("".join(current))
    return pieces


def is_quota_failure(error: BaseException) -> bool:
    """Report whether a failed keyring write failed for lack of room.

    Windows Credential Manager reports it through the Win32 error on the backend's exception, a file-backed keyring through the errno of
    the ``OSError`` it raised; either may be the cause of the error keyring re-raised.

    Args:
        error: The error the write raised.

    Returns:
        bool: ``True`` when the error, or one it was raised from, says the store is full.
    """
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        winerror = getattr(current, "winerror", None)
        if isinstance(winerror, int) and winerror in _WINDOWS_QUOTA_ERRORS:
            return True
        if isinstance(current, OSError) and current.errno in _POSIX_QUOTA_ERRORS:
            return True
        current = current.__cause__ or current.__context__
    return False


def _is_count(value: object) -> TypeGuard[int]:
    """Report whether a manifest field holds a non-negative integer.

    Args:
        value: The decoded field.

    Returns:
        TypeGuard[int]: ``True`` for an ``int`` that is not a ``bool`` and not negative.
    """
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class CredentialSource(Enum):
    """Source of stored credentials."""

    KEYRING = "keyring"
    ENV_FILE = "env_file"
    ENV_VAR = "env_var"
    OAUTH = "oauth"


@dataclass(frozen=True)
class StoredCredential:
    """Metadata for a stored credential.

    Attributes:
        provider: Instance id of the provider this credential belongs to.
        key_name: Human-readable name or label for the credential.
        created_at: When the credential was first stored.
        updated_at: When the credential was last updated.
        source: Where the credential originated from.
    """

    provider: str
    key_name: str
    created_at: datetime
    updated_at: datetime
    source: CredentialSource


class CredentialStore:
    """Secure credential storage using OS keyring with env fallback.

    This class provides thread-safe, async-compatible access to credentials
    stored in the operating system's secure credential storage (Windows
    Credential Manager on Windows, Keychain on macOS, Secret Service on Linux).

    If keyring is unavailable, falls back to CredentialLoader for .env files.

    Attributes:
        SERVICE_NAME: The keyring service name for Intellicrack credentials.
        METADATA_KEY: Key suffix for storing credential metadata.
    """

    SERVICE_NAME: Final[str] = "intellicrack"
    METADATA_KEY: Final[str] = "_metadata"

    def __init__(self, fallback_loader: CredentialLoader | None = None) -> None:
        """Initialize the CredentialStore with an optional fallback loader.

        Args:
            fallback_loader: CredentialLoader instance for env-file fallback. If None, creates a new one.
        """
        self._fallback_loader = fallback_loader or get_credential_loader()
        self._lock = asyncio.Lock()
        self._keyring: ModuleType | None = None
        self._keyring_checked: bool = False
        self._keyring_available: bool = False
        _logger.debug("credential_store_initialized", has_fallback_loader=fallback_loader is not None)

    _UNUSABLE_BACKEND_NAMES: ClassVar[frozenset[str]] = frozenset({
        "fail.Keyring",
        "null.Keyring",
    })

    def _check_keyring(self) -> bool:
        """Check if keyring backend is available and functional.

        Performs passive inspection of the active keyring backend instead of
        writing and deleting a probe key.  The previous approach mutated the
        user's keyring on every initialization, which could collide with
        legitimate keys named ``intellicrack_test`` and pollute audit logs.

        Returns:
            bool: True if keyring is available and the active backend is a
            real credential store (not a fail/null backend).
        """
        if self._keyring_checked:
            return self._keyring_available

        self._keyring_checked = True

        if _keyring_module is None:
            _logger.warning("keyring_unavailable", reason="library_not_installed")
            return False

        try:
            backend = _keyring_module.get_keyring()
        except (OSError, KeyError, ValueError, _KeyringError, _Win32CredentialError, RuntimeError) as e:
            _logger.warning("keyring_unavailable", error=str(e), exc_info=True)
            return False

        backend_module = getattr(type(backend), "__module__", "")
        backend_name = type(backend).__name__
        qualified_name = f"{backend_module.rsplit('.', 1)[-1]}.{backend_name}" if backend_module else backend_name

        if qualified_name in self._UNUSABLE_BACKEND_NAMES or backend_name in {"Keyring", "FailKeyring", "NullKeyring"}:
            _logger.warning(
                "keyring_unavailable",
                reason="backend_is_fail_or_null",
                backend=qualified_name,
            )
            return False

        priority = getattr(backend, "priority", None)
        if isinstance(priority, (int, float)) and priority <= 0:
            _logger.warning(
                "keyring_unavailable",
                reason="backend_priority_non_positive",
                backend=qualified_name,
                priority=priority,
            )
            return False

        self._keyring = _keyring_module
        self._keyring_available = True
        _logger.info("keyring_backend_available", backend=qualified_name)
        return True

    @cached_property
    def keyring_available(self) -> bool:
        """Check if keyring backend is available and functional.

        Returns:
            bool: True if keyring can be used for credential storage.
        """
        return self._check_keyring()

    def _get_keyring_key(self, provider: str) -> str:
        """Get the keyring key name for a provider.

        Args:
            provider: The provider.

        Returns:
            str: The key name for keyring storage.
        """
        return f"{self.SERVICE_NAME}_{provider}"

    @staticmethod
    def _serialize_credentials(creds: ProviderCredentials) -> str:
        """Serialize credentials to JSON for storage.

        Args:
            creds: Credentials to serialize.

        Returns:
            str: JSON string representation.
        """
        data = asdict(creds)
        return json.dumps(data, ensure_ascii=False)

    @staticmethod
    def _deserialize_credentials(data: str) -> ProviderCredentials:
        """Deserialize credentials from JSON.

        Args:
            data: JSON string to deserialize.

        Returns:
            ProviderCredentials: ProviderCredentials instance.

        Raises:
            CredentialStoreError: If deserialization fails.
        """
        try:
            parsed = json.loads(data)
            return ProviderCredentials(
                api_key=parsed.get("api_key"),
                api_base=parsed.get("api_base"),
                organization_id=parsed.get("organization_id"),
                project_id=parsed.get("project_id"),
            )
        except (json.JSONDecodeError, TypeError, KeyError) as e:
            _logger.warning("credential_deserialize_failed", error=str(e), exc_info=True)
            msg = f"Failed to deserialize credentials: {e}"
            raise CredentialStoreError(msg) from e

    @staticmethod
    def _serialize_metadata(metadata: StoredCredential) -> str:
        """Serialize credential metadata to JSON.

        Args:
            metadata: Metadata to serialize.

        Returns:
            str: JSON string representation.
        """
        data = {
            "provider": metadata.provider,
            "key_name": metadata.key_name,
            "created_at": metadata.created_at.isoformat(),
            "updated_at": metadata.updated_at.isoformat(),
            "source": metadata.source.value,
        }
        return json.dumps(data, ensure_ascii=False)

    @staticmethod
    def _deserialize_metadata(data: str, provider: str) -> StoredCredential:
        """Deserialize credential metadata from JSON.

        Args:
            data: JSON string to deserialize.
            provider: Provider for the metadata.

        Returns:
            StoredCredential: StoredCredential instance.
        """
        try:
            parsed = json.loads(data)
            return StoredCredential(
                provider=str(parsed["provider"]),
                key_name=parsed.get("key_name", provider),
                created_at=datetime.fromisoformat(parsed["created_at"]),
                updated_at=datetime.fromisoformat(parsed["updated_at"]),
                source=CredentialSource(parsed["source"]),
            )
        except (json.JSONDecodeError, TypeError, KeyError, ValueError):
            _logger.debug("metadata_deserialize_fallback", provider=provider, exc_info=True)
            now = datetime.now(UTC)
            return StoredCredential(
                provider=provider,
                key_name=provider,
                created_at=now,
                updated_at=now,
                source=CredentialSource.KEYRING,
            )

    def _read_blob(self, keyring: ModuleType, key: str) -> str | None:
        """Read one stored value, reassembling it when it was written in chunks.

        The read holds :data:`_KEYRING_LOCK`, so no write in this process can switch the value's chunks underneath it. A write from
        another process still can: a chunk found missing is followed by one more read, and only a value that is still incomplete then is
        reported.

        Runs on a worker thread; every call it makes blocks on the backend.

        Args:
            keyring: The keyring module to read through.
            key: The value's own keyring key.

        Returns:
            str | None: The whole value, or ``None`` when nothing is stored under ``key``.

        Raises:
            KeyringReadError: If a chunk the manifest names is missing or the reassembled value is not the recorded length, on a second
                read as well as the first.
        """
        with _KEYRING_LOCK:
            for attempt in range(1, _READ_ATTEMPTS + 1):
                primary: object = keyring.get_password(self.SERVICE_NAME, key)
                if primary is None:
                    return None
                stored = str(primary)
                manifest = ChunkManifest.parse(stored)
                if manifest is None:
                    return stored
                try:
                    return self._assemble(keyring, key, manifest)
                except KeyringReadError:
                    if attempt == _READ_ATTEMPTS or keyring.get_password(self.SERVICE_NAME, key) == primary:
                        raise
            return None

    def _assemble(self, keyring: ModuleType, key: str, manifest: ChunkManifest) -> str:
        """Join the chunks one manifest names.

        Args:
            keyring: The keyring module to read through.
            key: The value's own keyring key.
            manifest: The manifest stored under ``key``.

        Returns:
            str: The whole value.

        Raises:
            KeyringReadError: If a chunk is missing or the joined value is not the recorded length.
        """
        pieces: list[str] = []
        for index in range(manifest.count):
            piece: object = keyring.get_password(self.SERVICE_NAME, manifest.chunk_key(key, index))
            if piece is None:
                message = f"credential {key!r} is stored in {manifest.count} parts but part {index} is missing from the keyring"
                raise KeyringReadError(message)
            pieces.append(str(piece))
        value = "".join(pieces)
        if len(value) != manifest.length:
            message = f"credential {key!r} was reassembled from {manifest.count} parts but is not its recorded length"
            raise KeyringReadError(message)
        return value

    def _write_blob(self, keyring: ModuleType, key: str, value: str) -> None:
        """Store one value, splitting it across entries when it exceeds the Credential Manager blob limit.

        A value that fits is written directly under ``key``, exactly as before chunking existed. A larger one is written as a transaction:

        1. the new chunks' generation is recorded under a pending marker first, so a crash part-way through leaves a record of what to
           remove;
        2. the chunks are written, and if one fails -- the keyring is full, say -- every chunk already written is removed again and the
           failure propagates, leaving the value that was stored before untouched;
        3. the manifest naming the complete set replaces whatever was under ``key``;
        4. the previous value's chunks are removed, and then the pending marker.

        Chunks a crashed write left behind are removed before the next write or delete of the same value. The whole write holds
        :data:`_KEYRING_LOCK`. An existing entry that cannot be read does not block the write, because overwriting it is how the operator
        repairs it; only its old chunks, which cannot be located, are left behind.

        Runs on a worker thread; every call it makes blocks on the backend.

        Args:
            keyring: The keyring module to write through.
            key: The value's own keyring key.
            value: The value to store.
        """
        with _KEYRING_LOCK:
            self._recover_pending(keyring, key)
            previous: ChunkManifest | None = None
            try:
                previous_primary: object = keyring.get_password(self.SERVICE_NAME, key)
            except (OSError, ValueError, _KeyringError, _Win32CredentialError):
                _logger.warning("credential_previous_entry_unreadable", key_id=key, exc_info=True)
            else:
                previous = ChunkManifest.parse(str(previous_primary)) if previous_primary is not None else None
            if credential_blob_size(value) <= CRED_MAX_CREDENTIAL_BLOB_BYTES and ChunkManifest.parse(value) is None:
                keyring.set_password(self.SERVICE_NAME, key, value)
            else:
                self._write_chunked(keyring, key, value)
            if previous is not None:
                self._delete_chunks(keyring, key, previous)
            self._clear_pending(keyring, key)

    def _write_chunked(self, keyring: ModuleType, key: str, value: str) -> None:
        """Write a value as chunks and then its manifest, removing every chunk written if any step fails.

        A failure propagates from the backend once the chunks and the pending marker are removed. If the removal itself fails, the marker
        stays, and the next write or delete of the value finishes the job.

        Args:
            keyring: The keyring module to write through.
            key: The value's own keyring key.
            value: The value to store.
        """
        pieces = split_credential_blob(value)
        manifest = ChunkManifest(generation=secrets.token_hex(_CHUNK_GENERATION_BYTES), count=len(pieces), length=len(value))
        keyring.set_password(self.SERVICE_NAME, _pending_key(key), manifest.generation)
        written = 0
        committed = False
        try:
            for index, piece in enumerate(pieces):
                keyring.set_password(self.SERVICE_NAME, manifest.chunk_key(key, index), piece)
                written = index + 1
            keyring.set_password(self.SERVICE_NAME, key, manifest.serialize())
            committed = True
        finally:
            if not committed:
                self._delete_chunks(keyring, key, ChunkManifest(generation=manifest.generation, count=written, length=0))
                self._clear_pending(keyring, key)
        _logger.debug("credential_stored_in_chunks", key_id=key, chunk_count=manifest.count)

    def _recover_pending(self, keyring: ModuleType, key: str) -> None:
        """Remove the chunks an interrupted write left behind.

        The pending marker names the generation that was being written. Unless the manifest under ``key`` now names that generation --
        the write got as far as committing -- its chunks are orphans, and they are removed in order until one is missing.

        Args:
            keyring: The keyring module to delete through.
            key: The value's own keyring key.
        """
        generation: object = keyring.get_password(self.SERVICE_NAME, _pending_key(key))
        if generation is None:
            return
        primary: object = keyring.get_password(self.SERVICE_NAME, key)
        current = ChunkManifest.parse(str(primary)) if primary is not None else None
        if current is None or current.generation != str(generation):
            orphan = ChunkManifest(generation=str(generation), count=0, length=0)
            index = 0
            while keyring.get_password(self.SERVICE_NAME, orphan.chunk_key(key, index)) is not None:
                keyring.delete_password(self.SERVICE_NAME, orphan.chunk_key(key, index))
                index += 1
            _logger.info("credential_orphaned_chunks_removed", key_id=key, chunk_count=index)
        self._clear_pending(keyring, key)

    def _clear_pending(self, keyring: ModuleType, key: str) -> None:
        """Remove the pending marker of a value, if there is one.

        Args:
            keyring: The keyring module to delete through.
            key: The value's own keyring key.
        """
        if keyring.get_password(self.SERVICE_NAME, _pending_key(key)) is not None:
            keyring.delete_password(self.SERVICE_NAME, _pending_key(key))

    def _delete_chunks(self, keyring: ModuleType, key: str, manifest: ChunkManifest) -> None:
        """Remove the chunk entries one manifest names.

        A chunk that is already gone is not an error: the goal is that none remain.

        Args:
            keyring: The keyring module to delete through.
            key: The value's own keyring key.
            manifest: The manifest whose chunks are removed.
        """
        for index in range(manifest.count):
            chunk_key = manifest.chunk_key(key, index)
            if keyring.get_password(self.SERVICE_NAME, chunk_key) is not None:
                keyring.delete_password(self.SERVICE_NAME, chunk_key)

    def _delete_blob(self, keyring: ModuleType, key: str) -> bool:
        """Remove one stored value together with any chunks it was split into.

        Args:
            keyring: The keyring module to delete through.
            key: The value's own keyring key.

        Returns:
            bool: ``True`` when a value was stored and has been removed, ``False`` when nothing was stored.
        """
        with _KEYRING_LOCK:
            self._recover_pending(keyring, key)
            primary: object = keyring.get_password(self.SERVICE_NAME, key)
            if primary is None:
                return False
            manifest = ChunkManifest.parse(str(primary))
            keyring.delete_password(self.SERVICE_NAME, key)
            if manifest is not None:
                self._delete_chunks(keyring, key, manifest)
            return True

    async def _get_from_keyring(self, provider: str) -> ProviderCredentials | None:
        """Get credentials directly from keyring.

        Args:
            provider: Provider to get credentials for.

        Returns:
            ProviderCredentials | None: ProviderCredentials, or ``None`` when the keyring is unavailable or holds nothing for the provider.

        Raises:
            KeyringReadError: If the keyring holds an entry for the provider but it cannot be read or decoded.
        """
        if self._keyring is None:
            return None

        key = self._get_keyring_key(provider)
        keyring = self._keyring

        def _fetch() -> str | None:
            """Read the serialized credential blob for the provider key.

            Returns:
                str | None: Credential payload string, or ``None`` if absent.
            """
            return self._read_blob(keyring, key)

        try:
            data = await asyncio.to_thread(_fetch)
            return self._deserialize_credentials(data) if data else None
        except KeyringReadError:
            _logger.warning("keyring_get_failed", provider=provider, exc_info=True)
            raise
        except (OSError, KeyError, ValueError, _KeyringError, _Win32CredentialError, CredentialStoreError) as e:
            _logger.warning("keyring_get_failed", provider=provider, error=str(e), exc_info=True)
            msg = f"Failed to read credentials from the keyring: {e}"
            raise KeyringReadError(msg) from e

    async def _set_to_keyring(
        self,
        provider: str,
        credentials: ProviderCredentials,
        key_name: str | None = None,
        source: CredentialSource = CredentialSource.KEYRING,
    ) -> None:
        """Store credentials directly to keyring.

        Args:
            provider: Provider to store credentials for.
            credentials: Credentials to store.
            key_name: Optional human-readable name.
            source: Origin of the credentials being stored.

        Raises:
            KeyringUnavailableError: If keyring is not available.
            CredentialStoreFullError: If the keyring has no room for the credential. Nothing stored before is changed.
            CredentialStoreError: If storage fails for any other reason.
        """
        if self._keyring is None:
            _logger.warning("credential_set_keyring_unavailable", provider=provider)
            msg = "Keyring is not available"
            raise KeyringUnavailableError(msg)

        key = self._get_keyring_key(provider)
        metadata_key = f"{key}{self.METADATA_KEY}"
        data = self._serialize_credentials(credentials)

        now = datetime.now(UTC)
        existing_metadata = await self._get_metadata(provider)

        metadata = StoredCredential(
            provider=provider,
            key_name=key_name or provider,
            created_at=existing_metadata.created_at if existing_metadata else now,
            updated_at=now,
            source=source,
        )
        metadata_data = self._serialize_metadata(metadata)
        keyring = self._keyring

        def _store() -> None:
            """Persist credential and metadata payloads under the provider keys."""
            self._write_blob(keyring, key, data)
            self._write_blob(keyring, metadata_key, metadata_data)

        try:
            await asyncio.to_thread(_store)
            _logger.info("credentials_stored", provider=provider, store="keyring")
        except (OSError, KeyError, ValueError, _KeyringError, _Win32CredentialError) as e:
            _logger.warning("credential_store_failed", provider=provider, error=str(e), exc_info=True)
            if is_quota_failure(e):
                msg = (
                    f"The system keyring is full, so the credential for {provider} could not be saved ({e}). Remove credentials you no "
                    f"longer use -- on Windows, in Credential Manager under Windows Credentials -- and save again. The credential stored "
                    f"before is unchanged."
                )
                raise CredentialStoreFullError(msg) from e
            msg = f"Failed to store credentials: {e}"
            raise CredentialStoreError(msg) from e

    async def _get_metadata(self, provider: str) -> StoredCredential | None:
        """Get credential metadata from keyring.

        Args:
            provider: Provider to get metadata for.

        Returns:
            StoredCredential | None: StoredCredential metadata or None.
        """
        if self._keyring is None:
            return None

        key = f"{self._get_keyring_key(provider)}{self.METADATA_KEY}"
        keyring = self._keyring

        def _fetch() -> str | None:
            """Read the serialized metadata blob for the provider key.

            Returns:
                str | None: Metadata payload string, or ``None`` if absent.
            """
            return self._read_blob(keyring, key)

        try:
            data = await asyncio.to_thread(_fetch)
            return self._deserialize_metadata(data, provider) if data else None
        except (OSError, KeyError, ValueError, _KeyringError, _Win32CredentialError, KeyringReadError):
            _logger.debug("metadata_get_failed", provider=provider, exc_info=True)
            return None

    async def _get_unlocked(self, provider: str) -> ProviderCredentials | None:
        """Get credentials without acquiring ``self._lock``.

        This private helper performs the actual keyring read and env
        fallback. It is used internally by methods that already hold
        ``self._lock`` (such as :meth:`list_providers`) to avoid re-entrant
        lock acquisition which would deadlock ``asyncio.Lock``.

        A keyring entry that exists but cannot be read is logged and the
        env-file credential is used instead, which is the documented
        fallback for provider keys. Callers that must not fall back use
        :meth:`get_secret`.

        Args:
            provider: The provider to get credentials for.

        Returns:
            ProviderCredentials | None: ProviderCredentials if found, None otherwise.
        """
        if self.keyring_available:
            try:
                creds = await self._get_from_keyring(provider)
            except KeyringReadError as exc:
                _logger.warning("credential_keyring_unreadable_using_env", provider=provider, error=str(exc))
                creds = None
            if creds is not None and creds.api_key:
                return creds

        _logger.debug("credential_fallback_to_env", provider=provider)
        return await asyncio.to_thread(self._fallback_loader.get_credentials, provider)

    async def get(self, provider: str) -> ProviderCredentials | None:
        """Get credentials for a provider.

        Checks keyring first, then falls back to env loader.

        Args:
            provider: The provider to get credentials for.

        Returns:
            ProviderCredentials | None: ProviderCredentials if found, None otherwise.
        """
        _logger.debug("credential_get_started", provider=provider, key_id=self._get_keyring_key(provider))
        async with self._lock:
            result = await self._get_unlocked(provider)
        _logger.debug(
            "credential_get_completed",
            provider=provider,
            key_id=self._get_keyring_key(provider),
            credential_found=result is not None and bool(result.api_key),
        )
        return result

    async def get_secret(self, key: str) -> ProviderCredentials | None:
        """Read one value from the keyring alone, reporting every failure.

        Unlike :meth:`get`, nothing falls back to the env file and nothing
        is swallowed: ``None`` means the keyring was read and holds no entry
        under ``key``, and every other outcome raises. This is what a caller
        needs when "not stored" leads the operator to re-enter a secret.
        An entry that exists but cannot be read propagates
        :class:`KeyringReadError` from the read.

        Args:
            key: The credential key.

        Returns:
            ProviderCredentials | None: The stored credentials, or ``None``
            when the keyring holds nothing under ``key``.

        Raises:
            KeyringUnavailableError: If no usable keyring backend exists.
        """
        if not self.keyring_available:
            msg = "Keyring is not available, so the stored value cannot be read"
            raise KeyringUnavailableError(msg)
        async with self._lock:
            return await self._get_from_keyring(key)

    async def get_or_raise(self, provider: str) -> ProviderCredentials:
        """Get credentials for a provider, raising if not found.

        Args:
            provider: The provider to get credentials for.

        Returns:
            ProviderCredentials: ProviderCredentials for the provider.

        Raises:
            CredentialNotFoundError: If no credentials are found.
        """
        creds = await self.get(provider)
        if creds is None:
            _logger.warning("credential_get_or_raise_missing", provider=provider)
            msg = f"No credentials found for {provider}"
            raise CredentialNotFoundError(msg)
        return creds

    async def set(
        self,
        provider: str,
        credentials: ProviderCredentials,
        key_name: str | None = None,
        source: CredentialSource = CredentialSource.KEYRING,
    ) -> None:
        """Store credentials for a provider in keyring.

        Args:
            provider: The provider to store credentials for.
            credentials: The credentials to store.
            key_name: Optional human-readable name for the credential.
            source: Origin of the credentials being stored.

        Raises:
            KeyringUnavailableError: If keyring is not available.
        """
        _logger.debug(
            "credential_set_started",
            provider=provider,
            key_id=self._get_keyring_key(provider),
            source=source.value,
        )
        if not self.keyring_available:
            _logger.warning("credential_set_keyring_unavailable", provider=provider)
            msg = (
                "Keyring is not available. Install keyring package and ensure "
                "a backend is available (Windows Credential Manager, macOS Keychain, etc.)"
            )
            raise KeyringUnavailableError(msg)

        async with self._lock:
            await self._set_to_keyring(provider, credentials, key_name, source)

    async def delete(self, provider: str) -> bool:
        """Delete credentials for a provider from keyring.

        Args:
            provider: The provider to delete credentials for.

        Returns:
            bool: True if credentials were deleted, False if not found.

        Raises:
            KeyringUnavailableError: If keyring is not available.
        """
        if not self.keyring_available or self._keyring is None:
            _logger.warning("credential_delete_keyring_unavailable", provider=provider)
            msg = "Keyring is not available"
            raise KeyringUnavailableError(msg)

        key = self._get_keyring_key(provider)
        metadata_key = f"{key}{self.METADATA_KEY}"
        keyring = self._keyring
        _logger.info("credential_delete_started", provider=provider, key_id=key)

        def _delete() -> bool:
            """Remove credential and metadata entries for the provider keys.

            Returns:
                bool: ``True`` when the credential entry was deleted; ``False``
                when credential deletion itself failed.
            """
            try:
                if not self._delete_blob(keyring, key):
                    return False
            except (OSError, KeyError, ValueError, _KeyringError, _Win32CredentialError):
                _logger.exception("keyring_delete_credential_failed", provider=provider)
                return False
            try:
                _ = self._delete_blob(keyring, metadata_key)
            except (OSError, KeyError, ValueError, _KeyringError, _Win32CredentialError):
                _logger.exception("keyring_delete_metadata_failed", provider=provider)
            return True

        async with self._lock:
            result = await asyncio.to_thread(_delete)
            if result:
                _logger.info("credentials_deleted", provider=provider, key_id=key, store="keyring")
            return result

    async def list_providers(self) -> list[StoredCredential]:
        """List all stored credential metadata.

        Returns:
            list[StoredCredential]: List of StoredCredential with metadata for each provider.
        """
        _logger.debug("credential_list_providers_started")
        results: list[StoredCredential] = []

        async with self._lock:
            for provider in known_provider_ids():
                creds = await self._get_unlocked(provider)
                if creds is not None and creds.api_key:
                    metadata = await self._get_metadata(provider)
                    if metadata:
                        results.append(metadata)
                    else:
                        now = datetime.now(UTC)
                        results.append(
                            StoredCredential(
                                provider=provider,
                                key_name=provider,
                                created_at=now,
                                updated_at=now,
                                source=CredentialSource.ENV_FILE,
                            ),
                        )

        _logger.debug("credential_list_providers_completed", provider_count=len(results))
        return results

    async def migrate_from_env(
        self,
        providers: list[str] | None = None,
        *,
        overwrite: bool = False,
    ) -> dict[str, bool]:
        """Migrate credentials from .env file to keyring.

        Args:
            providers: Specific providers to migrate. If None, migrates all.
            overwrite: Whether to overwrite existing keyring credentials.

        Returns:
            dict[str, bool]: Dict mapping provider to success status.

        Raises:
            KeyringUnavailableError: If keyring is not available.
        """
        _logger.debug(
            "credential_migration_started",
            provider_count=len(providers) if providers is not None else len(known_provider_ids()),
            overwrite=overwrite,
        )
        if not self.keyring_available:
            _logger.warning("credential_migration_keyring_unavailable")
            msg = "Keyring is not available for migration"
            raise KeyringUnavailableError(msg)

        target_providers = providers or list(known_provider_ids())
        results: dict[str, bool] = {}

        async with self._lock:
            for provider in target_providers:
                env_creds = await asyncio.to_thread(self._fallback_loader.get_credentials, provider)
                if env_creds is None or not env_creds.api_key:
                    results[provider] = False
                    continue

                if not overwrite:
                    try:
                        existing = await self._get_from_keyring(provider)
                    except KeyringReadError as exc:
                        _logger.warning("credential_migration_failed", provider=provider, error=str(exc))
                        results[provider] = False
                        continue
                    if existing is not None and existing.api_key:
                        _logger.info("credential_migration_skipped", provider=provider, reason="exists")
                        results[provider] = True
                        continue

                try:
                    await self._set_to_keyring(
                        provider,
                        env_creds,
                        source=CredentialSource.ENV_FILE,
                    )
                    results[provider] = True
                    _logger.info("credentials_migrated", provider=provider, source="env", destination="keyring")
                except (OSError, KeyError, ValueError, _KeyringError, _Win32CredentialError, CredentialStoreError) as exc:
                    _logger.warning("credential_migration_failed", provider=provider, error=str(exc), exc_info=True)
                    results[provider] = False

        return results

    async def validate(self, provider: str) -> tuple[bool, str | None]:
        """Validate that a credential exists and is usable.

        Shape validation is deliberately minimal and delegates to
        :func:`~intellicrack.credentials.env_loader.validate_key_format`. The
        old rule rejected a key that did not start with the prefix the
        built-in provider of that name uses, which was wrong as soon as a
        provider id could name any endpoint: a gateway in front of Anthropic,
        an Azure deployment or a LiteLLM proxy all issue their own keys, and
        refusing them made the endpoint unusable for a cosmetic reason.

        Args:
            provider: The provider instance to validate.

        Returns:
            tuple[bool, str | None]: Tuple of (is_valid, error_message).
        """
        _logger.debug("credentials_validate_started", provider=provider)
        creds = await self.get(provider)
        if creds is None or not creds.api_key:
            _logger.debug("credentials_validate_no_credentials", provider=provider)
            return False, f"No credentials found for {provider}"
        problem = validate_key_format(provider, creds.api_key)
        return (problem is None), problem

    async def get_source(self, provider: str) -> CredentialSource | None:
        """Get the source of credentials for a provider.

        Args:
            provider: The provider to check.

        Returns:
            CredentialSource | None: CredentialSource or None if no credentials found.
        """
        _logger.debug("credentials_get_source_started", provider=provider)
        if self.keyring_available:
            try:
                keyring_creds = await self._get_from_keyring(provider)
            except KeyringReadError as exc:
                _logger.warning("credentials_get_source_keyring_unreadable", provider=provider, error=str(exc))
                keyring_creds = None
            if keyring_creds is not None and keyring_creds.api_key:
                metadata = await self._get_metadata(provider)
                source = metadata.source if metadata is not None else CredentialSource.KEYRING
                _logger.debug("credentials_get_source_completed", provider=provider, source=str(source))
                return source
        env_creds = await asyncio.to_thread(self._fallback_loader.get_credentials, provider)
        if env_creds is not None and env_creds.api_key:
            is_valid, source_desc = await asyncio.to_thread(self._fallback_loader.validate_credentials, provider)
            if is_valid and source_desc and "environment" in source_desc.lower():
                _logger.debug("credentials_get_source_completed", provider=provider, source="env_var")
                return CredentialSource.ENV_VAR
            _logger.debug("credentials_get_source_completed", provider=provider, source="env_file")
            return CredentialSource.ENV_FILE

        _logger.debug("credentials_get_source_completed", provider=provider, source="unset")
        return None


_store_lock = threading.Lock()


class _CredentialStoreHolder:
    """Holder for the module-level singleton credential store instance.

    Attributes:
        instance: The shared CredentialStore instance or ``None`` before init.
    """

    instance: CredentialStore | None = None


_store_holder = _CredentialStoreHolder()


def get_credential_store() -> CredentialStore:
    """Get the global credential store instance.

    Uses double-checked locking with a module-level :class:`threading.Lock`
    so concurrent callers from multiple threads cannot observe a partially
    constructed instance or race to create duplicates.

    Returns:
        CredentialStore: The singleton CredentialStore instance.
    """
    if _store_holder.instance is None:
        with _store_lock:
            if _store_holder.instance is None:
                _store_holder.instance = CredentialStore()
    return _store_holder.instance


async def get_credentials(provider: str) -> ProviderCredentials | None:
    """Get credentials for a provider using the global store.

    Args:
        provider: The provider to get credentials for.

    Returns:
        ProviderCredentials | None: ProviderCredentials or None if not configured.
    """
    store = get_credential_store()
    return await store.get(provider)
