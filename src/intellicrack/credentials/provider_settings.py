# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Saved provider settings for Intellicrack.

The Provider Settings dialog stores non-secret per-provider preferences --
whether a provider is enabled, its request timeout, default model and device
options -- in ``providers.json`` under the configuration directory. API keys
and endpoint settings (base URL, organization) live in the ``.env`` file owned
by :class:`~intellicrack.credentials.env_loader.CredentialLoader`, which is
authoritative for them. This module reads and writes ``providers.json``, turns
its contents into the policy applied when providers connect automatically, and
moves endpoint settings that earlier releases stored in ``providers.json`` into
``.env``.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import threading
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Final, cast

from intellicrack.core.logging import get_logger
from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials.env_loader import CredentialField, EnvPersistAction
from intellicrack.providers import ids as provider_ids
from intellicrack.providers.capabilities import CapabilityOverride


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from intellicrack.credentials.env_loader import CredentialLoader


_logger = get_logger(__name__)

PROVIDER_SETTINGS_FILENAME: Final[str] = "providers.json"
SETTINGS_SCHEMA_VERSION: Final[int] = 3
"""Schema version written into every provider section.

Version 3 only *adds* the top-level ``instances`` section; every v2 key stays
exactly where it was. ``_uses_current_schema`` tests ``version >=
SETTINGS_SCHEMA_VERSION``, so an older build reading a v3 file already treats
it as legacy and applies its own defaults rather than failing. A v3 file is
therefore still readable by a v2 build, which loses only the custom instances
it could not have used anyway.
"""

SCHEMA_VERSION_KEY: Final[str] = "schema_version"
MODEL_OVERRIDES_KEY: Final[str] = "model_overrides"
"""Key holding a provider section's per-model capability overrides."""

INSTANCES_KEY: Final[str] = "instances"
"""Top-level key holding user-defined provider instances.

It is a sibling of the per-provider sections rather than one of them, so it is
excluded from provider-section reads by name.
"""
ENABLED_KEY: Final[str] = "enabled"
TIMEOUT_SECONDS_KEY: Final[str] = "timeout_seconds"
LEGACY_DEFAULT_TIMEOUT_SECONDS: Final[int] = 120
LEGACY_ENDPOINT_KEYS: Final[tuple[tuple[str, CredentialField], ...]] = (
    ("api_base", CredentialField.API_BASE),
    ("organization_id", CredentialField.ORGANIZATION_ID),
)
_NON_PERSISTED_KEYS: Final[frozenset[str]] = frozenset({"api_key", *(key for key, _ in LEGACY_ENDPOINT_KEYS)})


def saved_model_overrides(section: Mapping[str, object]) -> dict[str, CapabilityOverride]:
    """Read the per-model capability overrides a provider section stores.

    This is the top layer of the capability merge: whatever the user stated
    for a specific model, which wins over both the endpoint's own metadata and
    the preset defaults. An entry that is not a JSON object is skipped rather
    than rejected, so one damaged record cannot cost the user the rest.

    Args:
        section: The provider's section from ``providers.json``.

    Returns:
        dict[str, CapabilityOverride]: Overrides keyed by model id.
    """
    raw = section.get(MODEL_OVERRIDES_KEY)
    if not isinstance(raw, dict):
        return {}
    overrides: dict[str, CapabilityOverride] = {}
    for model_id, entry in cast("dict[str, object]", raw).items():
        if isinstance(entry, dict):
            overrides[model_id] = CapabilityOverride.from_mapping(cast("dict[str, Any]", entry))
        else:
            _logger.warning("model_override_not_an_object", model=model_id)
    return overrides


def coerce_timeout_seconds(value: object) -> float | None:
    """Interpret a timeout value read from settings or the dialog.

    Args:
        value: The raw timeout value.

    Returns:
        float | None: A positive, finite timeout in seconds, or ``None`` when
        the value is missing, non-numeric, boolean, zero, negative or
        non-finite and therefore selects the provider default.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        return None
    return seconds


def _uses_current_schema(section: Mapping[str, object]) -> bool:
    """Report whether a provider section was written by the versioned schema.

    Args:
        section: One provider's saved settings.

    Returns:
        bool: True when the section carries a schema version of at least
        :data:`SETTINGS_SCHEMA_VERSION`.
    """
    version = section.get(SCHEMA_VERSION_KEY)
    return isinstance(version, int) and not isinstance(version, bool) and version >= SETTINGS_SCHEMA_VERSION


def saved_timeout_seconds(section: Mapping[str, object]) -> float | None:
    """Resolve the request timeout a saved provider section selects.

    Sections written before the settings schema was versioned always carried
    the dialog's untouched default of 120 seconds, so a legacy 120 selects the
    provider default. Versioned sections store ``null`` for the provider
    default, so every positive value they hold -- including 120 -- was chosen
    deliberately and applies.

    Args:
        section: One provider's saved settings.

    Returns:
        float | None: The timeout in seconds, or ``None`` for the provider default.
    """
    timeout = coerce_timeout_seconds(section.get(TIMEOUT_SECONDS_KEY))
    if timeout is None:
        return None
    if timeout == LEGACY_DEFAULT_TIMEOUT_SECONDS and not _uses_current_schema(section):
        return None
    return timeout


def saved_enabled(section: Mapping[str, object]) -> bool:
    """Resolve whether a saved provider section leaves the provider enabled.

    Args:
        section: One provider's saved settings.

    Returns:
        bool: The saved boolean flag, or True when the flag is absent or invalid.
    """
    value = section.get(ENABLED_KEY, True)
    return value if isinstance(value, bool) else True


def build_settings_section(values: Mapping[str, object]) -> dict[str, object]:
    """Build the ``providers.json`` section persisted for one provider.

    API keys and endpoint settings are excluded because ``.env`` owns them,
    and the section is stamped with the current schema version so its timeout
    is interpreted as deliberately chosen.

    Args:
        values: The provider's settings as collected by the dialog.

    Returns:
        dict[str, object]: The section to store.
    """
    section = {key: value for key, value in values.items() if key not in _NON_PERSISTED_KEYS}
    section[SCHEMA_VERSION_KEY] = SETTINGS_SCHEMA_VERSION
    return section


def _empty_timeouts() -> dict[str, float]:
    """Create an empty timeout mapping for :class:`ProviderConnectPolicy`.

    Returns:
        dict[str, float]: A new empty mapping.
    """
    return {}


@dataclass(frozen=True)
class ProviderConnectPolicy:
    """Policy applied when providers are connected automatically.

    Attributes:
        disabled: Providers that must not be connected automatically.
        timeouts: Request timeout overrides in seconds, keyed by provider.
    """

    disabled: frozenset[str] = frozenset()
    timeouts: Mapping[str, float] = field(default_factory=_empty_timeouts)

    def is_enabled(self, provider: str) -> bool:
        """Report whether a provider may be connected automatically.

        Args:
            provider: The provider.

        Returns:
            bool: True unless the provider is disabled.
        """
        return provider not in self.disabled

    def timeout_for(self, provider: str) -> float | None:
        """Return a provider's saved request timeout.

        Args:
            provider: The provider.

        Returns:
            float | None: The timeout in seconds, or ``None`` for the provider default.
        """
        return self.timeouts.get(provider)

    def apply_timeout(self, provider: str, credentials: ProviderCredentials) -> ProviderCredentials:
        """Return credentials carrying the provider's saved request timeout.

        Args:
            provider: The provider being connected.
            credentials: The credentials resolved for the provider.

        Returns:
            ProviderCredentials: ``credentials`` unchanged when no timeout is
            saved, otherwise a copy with the saved timeout.
        """
        timeout = self.timeout_for(provider)
        return credentials if timeout is None else replace(credentials, timeout=timeout)


@dataclass(frozen=True)
class LegacyEndpointMigration:
    """Outcome of :meth:`ProviderSettingsStore.migrate_legacy_endpoints`.

    Attributes:
        imported: ``.env`` variables written from legacy ``providers.json`` values.
        retained: ``<provider>.<field>`` entries kept in ``providers.json``
            because writing them to ``.env`` failed; their values still apply
            for the current session.
        settings_rewritten: Whether ``providers.json`` was rewritten without
            the migrated fields.
    """

    imported: tuple[str, ...] = ()
    retained: tuple[str, ...] = ()
    settings_rewritten: bool = False


class ProviderSettingsStore:
    """Reads and writes the ``providers.json`` provider settings file."""

    def __init__(self, path: Path) -> None:
        """Initialize the store for a settings file.

        Args:
            path: Location of ``providers.json``; it need not exist yet.
        """
        self._path = path
        self._lock = threading.RLock()

    def load(self) -> dict[str, dict[str, object]]:
        """Load every provider section.

        A missing, unreadable or malformed file yields an empty mapping and
        entries that are not JSON objects are skipped, so a damaged file never
        prevents the application from starting.

        Returns:
            dict[str, dict[str, object]]: Provider sections keyed by provider id.
        """
        try:
            text = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            _logger.warning("provider_settings_read_failed", path=str(self._path), error=str(exc))
            return {}

        try:
            payload: object = json.loads(text)
        except json.JSONDecodeError as exc:
            _logger.warning("provider_settings_parse_failed", path=str(self._path), error=str(exc))
            return {}

        if not isinstance(payload, dict):
            _logger.warning("provider_settings_not_an_object", path=str(self._path))
            return {}

        sections: dict[str, dict[str, object]] = {}
        for provider_id, section in cast("dict[str, object]", payload).items():
            if provider_id == INSTANCES_KEY:
                continue
            if isinstance(section, dict):
                sections[provider_id] = cast("dict[str, object]", section)
        return sections

    def _load_raw(self) -> dict[str, object]:
        """Load the whole settings file, including non-provider sections.

        Returns:
            dict[str, object]: The decoded file, or an empty mapping when it
            is missing, unreadable or malformed.
        """
        try:
            text = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            _logger.warning("provider_settings_read_failed", path=str(self._path), error=str(exc))
            return {}
        try:
            payload: object = json.loads(text)
        except json.JSONDecodeError as exc:
            _logger.warning("provider_settings_parse_failed", path=str(self._path), error=str(exc))
            return {}
        return cast("dict[str, object]", payload) if isinstance(payload, dict) else {}

    def load_instances(self) -> dict[str, dict[str, object]]:
        """Load every saved provider instance.

        Returns:
            dict[str, dict[str, object]]: Instance records keyed by instance
            id. Entries that are not JSON objects are skipped, so one damaged
            record cannot cost the user the rest.
        """
        raw = self._load_raw().get(INSTANCES_KEY)
        if not isinstance(raw, dict):
            return {}
        instances: dict[str, dict[str, object]] = {}
        for instance_id, record in cast("dict[str, object]", raw).items():
            if isinstance(record, dict):
                instances[instance_id] = cast("dict[str, object]", record)
            else:
                _logger.warning("provider_instance_record_not_an_object", instance_id=instance_id)
        return instances

    def write_instance(self, instance_id: str, record: Mapping[str, object]) -> None:
        """Store one provider instance, preserving every other section.

        Args:
            instance_id: The instance's id.
            record: The complete instance record to store. It must never
                contain a secret; keys live in the credential store. An
                ``OSError`` from writing the file propagates to the caller and
                leaves the previous file intact.
        """
        with self._lock:
            payload = self._load_raw()
            raw = payload.get(INSTANCES_KEY)
            instances: dict[str, object] = cast("dict[str, object]", raw) if isinstance(raw, dict) else {}
            instances[instance_id] = dict(record)
            payload[INSTANCES_KEY] = instances
            self._write_payload(payload)

    def delete_instance(self, instance_id: str) -> bool:
        """Remove one saved provider instance.

        Args:
            instance_id: The instance's id.

        Returns:
            bool: ``True`` when a record was removed. An ``OSError`` from
            writing the file propagates to the caller and leaves the previous
            file intact.
        """
        with self._lock:
            payload = self._load_raw()
            raw = payload.get(INSTANCES_KEY)
            if not isinstance(raw, dict):
                return False
            instances: dict[str, object] = cast("dict[str, object]", raw)
            if instances.pop(instance_id, None) is None:
                return False
            payload[INSTANCES_KEY] = instances
            self._write_payload(payload)
            return True

    def section(self, provider_id: str) -> dict[str, object]:
        """Return one provider's saved section.

        Args:
            provider_id: The provider identifier.

        Returns:
            dict[str, object]: The section, or an empty mapping when none is saved.
        """
        return self.load().get(provider_id, {})

    def write_section(self, provider_id: str, section: Mapping[str, object]) -> None:
        """Replace one provider's section while preserving every other section.

        The file is replaced atomically; an ``OSError`` from writing it
        propagates to the caller and leaves the previous file intact.

        Args:
            provider_id: The provider identifier.
            section: The complete section to store.
        """
        with self._lock:
            payload = self._load_raw()
            payload[provider_id] = dict(section)
            self._write_payload(payload)

    def timeout_seconds(self, provider: str) -> float | None:
        """Return a provider's saved request timeout.

        Args:
            provider: The provider.

        Returns:
            float | None: The timeout in seconds, or ``None`` for the provider default.
        """
        return saved_timeout_seconds(self.section(provider))

    def connect_policy(self, config_enabled: Callable[[str], bool] | None = None) -> ProviderConnectPolicy:
        """Build the automatic-connection policy from the saved settings.

        Args:
            config_enabled: Optional additional enablement source, such as the
                application configuration's per-provider flag. A provider is
                disabled when either source disables it.

        Returns:
            ProviderConnectPolicy: The disabled providers and timeout overrides.
        """
        sections = self.load()
        disabled: set[str] = set()
        timeouts: dict[str, float] = {}
        for provider in provider_ids.BUILTIN_PROVIDER_IDS:
            section = sections.get(provider, {})
            if not saved_enabled(section) or (config_enabled is not None and not config_enabled(provider)):
                disabled.add(provider)
            timeout = saved_timeout_seconds(section)
            if timeout is not None:
                timeouts[provider] = timeout
        return ProviderConnectPolicy(disabled=frozenset(disabled), timeouts=timeouts)

    def migrate_legacy_endpoints(self, loader: CredentialLoader) -> LegacyEndpointMigration:
        """Move endpoint settings stored by earlier releases into ``.env``.

        Earlier releases saved each provider's base URL and organization only
        in ``providers.json``, where startup never read them. For every such
        field whose ``.env`` variable is not already saved, the value is
        persisted through the loader; a value ``.env`` already holds wins and
        the legacy copy is discarded. Migrated fields are then removed from
        ``providers.json`` so they cannot be imported again after being
        cleared. When writing ``.env`` fails, the loader still holds the value
        in memory -- :meth:`CredentialLoader.save_to_env_file` applies it before
        touching the file -- so it applies for this session, and the legacy
        field is kept for the next attempt.

        Args:
            loader: The credential loader bound to the application's ``.env``.

        Returns:
            LegacyEndpointMigration: What was imported, retained and rewritten.
        """
        with self._lock:
            sections = self.load()
            imported: list[str] = []
            retained: list[str] = []
            changed = False
            for provider_id, section in sections.items():
                if not provider_ids.is_valid_provider_id(provider_id):
                    continue
                provider = provider_ids.normalize_provider_id(provider_id)
                section_imported, section_retained, section_changed = self._migrate_section(loader, provider, section)
                imported.extend(section_imported)
                retained.extend(section_retained)
                changed = changed or section_changed

            rewritten = False
            if changed:
                try:
                    self._write(sections)
                except OSError as exc:
                    _logger.warning("provider_settings_migration_rewrite_failed", path=str(self._path), error=str(exc))
                else:
                    rewritten = True

        if changed or retained:
            _logger.info(
                "provider_settings_endpoints_migrated",
                imported=imported,
                retained=retained,
                settings_rewritten=rewritten,
            )
        return LegacyEndpointMigration(imported=tuple(imported), retained=tuple(retained), settings_rewritten=rewritten)

    @staticmethod
    def _migrate_section(
        loader: CredentialLoader,
        provider: str,
        section: dict[str, object],
    ) -> tuple[list[str], list[str], bool]:
        """Migrate one provider section's legacy endpoint fields, mutating it.

        Args:
            loader: The credential loader bound to the application's ``.env``.
            provider: The provider the section belongs to.
            section: The provider's section; migrated fields are deleted from it.

        Returns:
            tuple[list[str], list[str], bool]: The ``.env`` variables written,
            the retained ``<provider>.<field>`` entries, and whether the
            section changed.
        """
        imported: list[str] = []
        retained: list[str] = []
        changed = False
        for json_key, credential_field in LEGACY_ENDPOINT_KEYS:
            env_var = loader.env_var_for(provider, credential_field)
            if json_key not in section or env_var is None:
                continue
            raw_value = section[json_key]
            value = raw_value.strip() if isinstance(raw_value, str) else ""
            if value and loader.get_saved_var(env_var) is None:
                try:
                    action = loader.persist_field(provider, credential_field, value)
                except OSError as exc:
                    _logger.warning(
                        "provider_settings_endpoint_import_failed",
                        provider=provider,
                        variable=env_var,
                        error=str(exc),
                    )
                    retained.append(f"{provider}.{json_key}")
                    continue
                if action is EnvPersistAction.WRITTEN:
                    imported.append(env_var)
            del section[json_key]
            changed = True
        return imported, retained, changed

    def _write(self, sections: Mapping[str, Mapping[str, object]]) -> None:
        """Atomically replace the provider sections, preserving other sections.

        Args:
            sections: Every provider section to store. An ``OSError`` from
                writing the file propagates to the caller and leaves the
                previous file intact.
        """
        payload = self._load_raw()
        for key in [name for name in payload if name != INSTANCES_KEY]:
            del payload[key]
        payload.update({name: dict(section) for name, section in sections.items()})
        self._write_payload(payload)

    def _write_payload(self, payload: Mapping[str, object]) -> None:
        """Atomically replace the whole settings file.

        Args:
            payload: The complete file contents to store.

        Raises:
            OSError: If the file cannot be written or moved into place.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_name(f"{self._path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            temporary.replace(self._path)
        except OSError:
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)
            _logger.exception("provider_settings_write_failed", path=str(self._path))
            raise


def resolve_session_credentials(
    provider: str,
    stored: ProviderCredentials | None,
    *,
    loader: CredentialLoader,
    settings: ProviderSettingsStore,
    api_key_optional: bool,
) -> ProviderCredentials:
    """Build the credentials used to connect a provider on demand.

    Credentials from the credential store take precedence. When the store has
    none, providers that work without an API key fall back to their saved
    endpoint settings so a custom host is not lost. The saved request timeout
    is applied in both cases.

    Args:
        provider: The provider being connected.
        stored: Credentials returned by the credential store, if any.
        loader: The credential loader bound to the application's ``.env``.
        settings: The provider settings store.
        api_key_optional: Whether the provider can connect without an API key.

    Returns:
        ProviderCredentials: The credentials to connect with.
    """
    resolved = stored if stored is not None else loader.get_connect_credentials(provider, api_key_optional=api_key_optional)
    credentials = resolved if resolved is not None else ProviderCredentials()
    timeout = settings.timeout_seconds(provider)
    return credentials if timeout is None else replace(credentials, timeout=timeout)
