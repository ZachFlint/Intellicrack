"""Secure credential storage using OS keyring.

This module provides secure credential storage using the operating system's
native credential manager (Windows Credential Manager, macOS Keychain,
or Linux Secret Service via the keyring library).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from functools import cached_property
from types import ModuleType
from typing import Final

from ..core.logging import get_logger
from ..core.types import IntellicrackError, ProviderCredentials, ProviderName
from .env_loader import CredentialLoader, get_credential_loader


_logger = get_logger("credentials.store")


class CredentialStoreError(IntellicrackError):
    """Base error for credential store operations."""

    pass


class KeyringUnavailableError(CredentialStoreError):
    """Keyring backend is not available."""

    pass


class CredentialNotFoundError(CredentialStoreError):
    """Requested credential was not found."""

    pass


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
        provider: The provider this credential belongs to.
        key_name: Human-readable name/label for the credential.
        created_at: When the credential was first stored.
        updated_at: When the credential was last updated.
        source: Where the credential originated from.
    """

    provider: ProviderName
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
        """Initialize the credential store.

        Args:
            fallback_loader: CredentialLoader instance for fallback.
                           If None, creates a new one.
        """
        self._fallback_loader = fallback_loader or get_credential_loader()
        self._lock = asyncio.Lock()
        self._keyring: ModuleType | None = None
        self._keyring_checked: bool = False
        self._keyring_available: bool = False

    def _check_keyring(self) -> bool:
        """Check if keyring backend is available and functional.

        Returns:
            True if keyring is available and working.
        """
        if self._keyring_checked:
            return self._keyring_available

        self._keyring_checked = True

        try:
            import keyring

            test_key = f"{self.SERVICE_NAME}_test"
            keyring.set_password(self.SERVICE_NAME, test_key, "test_value")
            result = keyring.get_password(self.SERVICE_NAME, test_key)
            keyring.delete_password(self.SERVICE_NAME, test_key)

            if result == "test_value":
                self._keyring = keyring
                self._keyring_available = True
                _logger.info("keyring_backend_available", extra={"backend": keyring.get_keyring().__class__.__name__})
                return True

            _logger.warning("keyring_test_failed", extra={"reason": "value_mismatch"})
            return False

        except ImportError:
            _logger.warning("keyring_unavailable", extra={"reason": "library_not_installed"})
            return False
        except Exception as e:
            _logger.warning("keyring_unavailable", extra={"error": str(e)})
            return False

    @cached_property
    def keyring_available(self) -> bool:
        """Check if keyring backend is available and functional.

        Returns:
            True if keyring can be used for credential storage.
        """
        return self._check_keyring()

    def _get_keyring_key(self, provider: ProviderName) -> str:
        """Get the keyring key name for a provider.

        Args:
            provider: The provider.

        Returns:
            The key name for keyring storage.
        """
        return f"{self.SERVICE_NAME}_{provider.value}"

    def _serialize_credentials(self, creds: ProviderCredentials) -> str:
        """Serialize credentials to JSON for storage.

        Args:
            creds: Credentials to serialize.

        Returns:
            JSON string representation.
        """
        data = asdict(creds)
        return json.dumps(data, ensure_ascii=False)

    def _deserialize_credentials(self, data: str) -> ProviderCredentials:
        """Deserialize credentials from JSON.

        Args:
            data: JSON string to deserialize.

        Returns:
            ProviderCredentials instance.

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
            raise CredentialStoreError(f"Failed to deserialize credentials: {e}") from e

    def _serialize_metadata(self, metadata: StoredCredential) -> str:
        """Serialize credential metadata to JSON.

        Args:
            metadata: Metadata to serialize.

        Returns:
            JSON string representation.
        """
        data = {
            "provider": metadata.provider.value,
            "key_name": metadata.key_name,
            "created_at": metadata.created_at.isoformat(),
            "updated_at": metadata.updated_at.isoformat(),
            "source": metadata.source.value,
        }
        return json.dumps(data, ensure_ascii=False)

    def _deserialize_metadata(self, data: str, provider: ProviderName) -> StoredCredential:
        """Deserialize credential metadata from JSON.

        Args:
            data: JSON string to deserialize.
            provider: Provider for the metadata.

        Returns:
            StoredCredential instance.
        """
        try:
            parsed = json.loads(data)
            return StoredCredential(
                provider=ProviderName(parsed["provider"]),
                key_name=parsed.get("key_name", provider.value),
                created_at=datetime.fromisoformat(parsed["created_at"]),
                updated_at=datetime.fromisoformat(parsed["updated_at"]),
                source=CredentialSource(parsed["source"]),
            )
        except (json.JSONDecodeError, TypeError, KeyError, ValueError):
            _logger.debug("metadata_deserialize_fallback", extra={"provider": provider.value})
            now = datetime.now(UTC)
            return StoredCredential(
                provider=provider,
                key_name=provider.value,
                created_at=now,
                updated_at=now,
                source=CredentialSource.KEYRING,
            )

    async def _get_from_keyring(self, provider: ProviderName) -> ProviderCredentials | None:
        """Get credentials directly from keyring.

        Args:
            provider: Provider to get credentials for.

        Returns:
            ProviderCredentials or None if not found.
        """
        if self._keyring is None:
            return None

        key = self._get_keyring_key(provider)
        keyring = self._keyring

        def _fetch() -> str | None:
            result = keyring.get_password(self.SERVICE_NAME, key)
            return str(result) if result is not None else None

        try:
            data = await asyncio.to_thread(_fetch)
            return self._deserialize_credentials(data) if data else None
        except Exception as e:
            _logger.warning("keyring_get_failed", extra={"provider": provider.value, "error": str(e)})
            return None

    async def _set_to_keyring(
        self,
        provider: ProviderName,
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
            CredentialStoreError: If storage fails.
        """
        if self._keyring is None:
            raise KeyringUnavailableError("Keyring is not available")

        key = self._get_keyring_key(provider)
        metadata_key = f"{key}{self.METADATA_KEY}"
        data = self._serialize_credentials(credentials)

        now = datetime.now(UTC)
        existing_metadata = await self._get_metadata(provider)

        metadata = StoredCredential(
            provider=provider,
            key_name=key_name or provider.value,
            created_at=existing_metadata.created_at if existing_metadata else now,
            updated_at=now,
            source=source,
        )
        metadata_data = self._serialize_metadata(metadata)
        keyring = self._keyring

        def _store() -> None:
            keyring.set_password(self.SERVICE_NAME, key, data)
            keyring.set_password(self.SERVICE_NAME, metadata_key, metadata_data)

        try:
            await asyncio.to_thread(_store)
            _logger.info("credentials_stored", extra={"provider": provider.value, "store": "keyring"})
        except Exception as e:
            raise CredentialStoreError(f"Failed to store credentials: {e}") from e

    async def _get_metadata(self, provider: ProviderName) -> StoredCredential | None:
        """Get credential metadata from keyring.

        Args:
            provider: Provider to get metadata for.

        Returns:
            StoredCredential metadata or None.
        """
        if self._keyring is None:
            return None

        key = f"{self._get_keyring_key(provider)}{self.METADATA_KEY}"
        keyring = self._keyring

        def _fetch() -> str | None:
            result = keyring.get_password(self.SERVICE_NAME, key)
            return str(result) if result is not None else None

        try:
            data = await asyncio.to_thread(_fetch)
            return self._deserialize_metadata(data, provider) if data else None
        except Exception:
            _logger.debug("metadata_get_failed", extra={"provider": provider.value})
            return None

    async def get(self, provider: ProviderName) -> ProviderCredentials | None:
        """Get credentials for a provider.

        Checks keyring first, then falls back to env loader.

        Args:
            provider: The provider to get credentials for.

        Returns:
            ProviderCredentials if found, None otherwise.
        """
        async with self._lock:
            if self.keyring_available:
                creds = await self._get_from_keyring(provider)
                if creds is not None and creds.api_key:
                    return creds

            _logger.debug("credential_fallback_to_env", extra={"provider": provider.value})
            return self._fallback_loader.get_credentials(provider)

    async def get_or_raise(self, provider: ProviderName) -> ProviderCredentials:
        """Get credentials for a provider, raising if not found.

        Args:
            provider: The provider to get credentials for.

        Returns:
            ProviderCredentials for the provider.

        Raises:
            CredentialNotFoundError: If no credentials are found.
        """
        creds = await self.get(provider)
        if creds is None:
            raise CredentialNotFoundError(f"No credentials found for {provider.value}")
        return creds

    async def set(
        self,
        provider: ProviderName,
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
        if not self.keyring_available:
            raise KeyringUnavailableError(
                "Keyring is not available. Install keyring package and ensure "
                "a backend is available (Windows Credential Manager, macOS Keychain, etc.)"
            )

        async with self._lock:
            await self._set_to_keyring(provider, credentials, key_name, source)

    async def delete(self, provider: ProviderName) -> bool:
        """Delete credentials for a provider from keyring.

        Args:
            provider: The provider to delete credentials for.

        Returns:
            True if credentials were deleted, False if not found.

        Raises:
            KeyringUnavailableError: If keyring is not available.
        """
        if not self.keyring_available or self._keyring is None:
            raise KeyringUnavailableError("Keyring is not available")

        key = self._get_keyring_key(provider)
        metadata_key = f"{key}{self.METADATA_KEY}"
        keyring = self._keyring

        def _delete() -> bool:
            try:
                keyring.delete_password(self.SERVICE_NAME, key)
            except Exception:
                _logger.debug("keyring_delete_credential_failed", extra={"provider": provider.value})
                return False
            try:
                keyring.delete_password(self.SERVICE_NAME, metadata_key)
            except Exception:
                _logger.debug("keyring_delete_metadata_failed", extra={"provider": provider.value})
            return True

        async with self._lock:
            result = await asyncio.to_thread(_delete)
            if result:
                _logger.info("credentials_deleted", extra={"provider": provider.value, "store": "keyring"})
            return result

    async def list_providers(self) -> list[StoredCredential]:
        """List all stored credential metadata.

        Returns:
            List of StoredCredential with metadata for each provider.
        """
        results: list[StoredCredential] = []

        async with self._lock:
            for provider in ProviderName:
                creds = await self.get(provider)
                if creds is not None and creds.api_key:
                    metadata = await self._get_metadata(provider)
                    if metadata:
                        results.append(metadata)
                    else:
                        now = datetime.now(UTC)
                        results.append(
                            StoredCredential(
                                provider=provider,
                                key_name=provider.value,
                                created_at=now,
                                updated_at=now,
                                source=CredentialSource.ENV_FILE,
                            )
                        )

        return results

    async def migrate_from_env(
        self,
        providers: list[ProviderName] | None = None,
        overwrite: bool = False,
    ) -> dict[ProviderName, bool]:
        """Migrate credentials from .env file to keyring.

        Args:
            providers: Specific providers to migrate. If None, migrates all.
            overwrite: Whether to overwrite existing keyring credentials.

        Returns:
            Dict mapping provider to success status.

        Raises:
            KeyringUnavailableError: If keyring is not available.
        """
        if not self.keyring_available:
            raise KeyringUnavailableError("Keyring is not available for migration")

        target_providers = providers or list(ProviderName)
        results: dict[ProviderName, bool] = {}

        async with self._lock:
            for provider in target_providers:
                env_creds = self._fallback_loader.get_credentials(provider)
                if env_creds is None or not env_creds.api_key:
                    results[provider] = False
                    continue

                if not overwrite:
                    existing = await self._get_from_keyring(provider)
                    if existing is not None and existing.api_key:
                        _logger.info("credential_migration_skipped", extra={"provider": provider.value, "reason": "exists"})
                        results[provider] = True
                        continue

                try:
                    await self._set_to_keyring(
                        provider,
                        env_creds,
                        source=CredentialSource.ENV_FILE,
                    )
                    results[provider] = True
                    _logger.info("credentials_migrated", extra={"provider": provider.value, "from": "env", "to": "keyring"})
                except Exception:
                    _logger.exception("credential_migration_failed", extra={"provider": provider.value})
                    results[provider] = False

        return results

    async def validate(self, provider: ProviderName) -> tuple[bool, str | None]:
        """Validate credentials exist and are properly formatted.

        Args:
            provider: The provider to validate.

        Returns:
            Tuple of (is_valid, error_message).
        """
        creds = await self.get(provider)
        if creds is None or not creds.api_key:
            return False, f"No credentials found for {provider.value}"

        if provider == ProviderName.ANTHROPIC:
            if not creds.api_key.startswith("sk-ant-"):
                return False, "Anthropic API key should start with 'sk-ant-'"

        elif provider == ProviderName.OPENAI:
            if not creds.api_key.startswith("sk-"):
                return False, "OpenAI API key should start with 'sk-'"

        elif provider == ProviderName.OPENROUTER:
            if not creds.api_key.startswith("sk-or-"):
                return False, "OpenRouter API key should start with 'sk-or-'"

        return True, None

    async def get_source(self, provider: ProviderName) -> CredentialSource | None:
        """Get the source of credentials for a provider.

        Args:
            provider: The provider to check.

        Returns:
            CredentialSource or None if no credentials found.
        """
        if self.keyring_available:
            keyring_creds = await self._get_from_keyring(provider)
            if keyring_creds is not None and keyring_creds.api_key:
                metadata = await self._get_metadata(provider)
                if metadata is not None:
                    return metadata.source
                return CredentialSource.KEYRING

        env_creds = self._fallback_loader.get_credentials(provider)
        if env_creds is not None and env_creds.api_key:
            is_valid, source_desc = self._fallback_loader.validate_credentials(provider)
            if is_valid and source_desc and "environment" in source_desc.lower():
                return CredentialSource.ENV_VAR
            return CredentialSource.ENV_FILE

        return None


_credential_store: CredentialStore | None = None


def get_credential_store() -> CredentialStore:
    """Get the global credential store instance.

    Returns:
        The singleton CredentialStore instance.
    """
    global _credential_store
    if _credential_store is None:
        _credential_store = CredentialStore()
    return _credential_store


async def get_credentials(provider: ProviderName) -> ProviderCredentials | None:
    """Get credentials for a provider using the global store.

    Args:
        provider: The provider to get credentials for.

    Returns:
        ProviderCredentials or None if not configured.
    """
    store = get_credential_store()
    return await store.get(provider)
