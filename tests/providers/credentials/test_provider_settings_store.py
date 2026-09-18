# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the saved provider settings file (``providers.json``).

Drives the real :class:`ProviderSettingsStore` against real ``providers.json``
and ``.env`` files and fails when:

* a base URL or organization that an earlier release stored only in
  ``providers.json`` never reaches ``.env`` -- the file startup reads -- or can
  be imported again after the user cleared it;
* a ``.env`` value is overwritten by a stale ``providers.json`` copy;
* a failed ``.env`` write silently drops the saved endpoint;
* the old untouched 120-second default is applied as a deliberate timeout,
  or a deliberately chosen timeout is ignored;
* a provider disabled in either ``providers.json`` or the application
  configuration is still connected automatically;
* on-demand session connects lose a keyless provider's saved host or timeout.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.config import Config, ProviderConfig
from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials.env_loader import CredentialField, CredentialLoader
from intellicrack.credentials.provider_settings import (
    SCHEMA_VERSION_KEY,
    SETTINGS_SCHEMA_VERSION,
    ProviderSettingsStore,
    build_settings_section,
    coerce_timeout_seconds,
    resolve_session_credentials,
    saved_timeout_seconds,
)
from intellicrack.providers import ids as provider_ids
from tests._helpers.provider_state import isolate_provider_environment


if TYPE_CHECKING:
    from pathlib import Path


_OPENAI_KEY = "sk-" + ("s" * 48)
_LEGACY_BASE_URL = "https://api.venice.example/api/v1"
_ENV_BASE_URL = "https://gateway.example/v1"


@pytest.fixture(autouse=True)
def clean_provider_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every gate from an environment without provider variables.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    isolate_provider_environment(monkeypatch)


def _write_settings(path: Path, sections: dict[str, dict[str, object]]) -> ProviderSettingsStore:
    """Write a real ``providers.json`` and open a store on it.

    Args:
        path: Settings file location.
        sections: Provider sections to write.

    Returns:
        ProviderSettingsStore: A store bound to ``path``.
    """
    _ = path.write_text(json.dumps(sections, indent=2), encoding="utf-8")
    return ProviderSettingsStore(path)


def _read_settings(path: Path) -> dict[str, dict[str, object]]:
    """Read ``providers.json`` back from disk.

    Args:
        path: Settings file location.

    Returns:
        dict[str, dict[str, object]]: The decoded sections.
    """
    decoded: dict[str, dict[str, object]] = json.loads(path.read_text(encoding="utf-8"))
    return decoded


def test_legacy_endpoint_settings_move_into_env_and_leave_providers_json(tmp_path: Path) -> None:
    """A base URL and organization saved only in ``providers.json`` reach ``.env``.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = tmp_path / ".env"
    _ = env_path.write_text(f"OPENAI_API_KEY={_OPENAI_KEY}\n", encoding="utf-8")
    settings_path = tmp_path / "providers.json"
    store = _write_settings(
        settings_path,
        {
            "openai": {
                "enabled": True,
                "api_base": _LEGACY_BASE_URL,
                "organization_id": "org-legacy",
                "default_model": "venice-uncensored",
                "timeout_seconds": 120,
                "max_retries": 3,
            },
        },
    )

    migration = store.migrate_legacy_endpoints(CredentialLoader(env_path))

    assert migration.imported == ("OPENAI_API_BASE", "OPENAI_ORGANIZATION")
    assert migration.retained == ()
    assert migration.settings_rewritten is True
    next_launch = CredentialLoader(env_path).get_credentials(provider_ids.OPENAI)
    assert next_launch is not None
    assert next_launch.api_base == _LEGACY_BASE_URL
    assert next_launch.organization_id == "org-legacy"
    openai_section = _read_settings(settings_path)["openai"]
    assert "api_base" not in openai_section
    assert "organization_id" not in openai_section
    assert openai_section["default_model"] == "venice-uncensored"
    assert openai_section["timeout_seconds"] == 120


def test_env_value_wins_over_stale_providers_json_copy(tmp_path: Path) -> None:
    """A base URL already saved in ``.env`` is kept; the legacy copy is discarded.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = tmp_path / ".env"
    _ = env_path.write_text(f'OPENAI_API_KEY={_OPENAI_KEY}\nOPENAI_API_BASE="{_ENV_BASE_URL}"\n', encoding="utf-8")
    settings_path = tmp_path / "providers.json"
    store = _write_settings(settings_path, {"openai": {"enabled": True, "api_base": _LEGACY_BASE_URL}})

    migration = store.migrate_legacy_endpoints(CredentialLoader(env_path))

    assert migration.imported == ()
    assert CredentialLoader(env_path).get_field(provider_ids.OPENAI, CredentialField.API_BASE) == _ENV_BASE_URL
    assert "api_base" not in _read_settings(settings_path)["openai"]


def test_cleared_endpoint_is_not_resurrected_by_a_later_launch(tmp_path: Path) -> None:
    """After migration and a user clear, the next launch does not re-import the legacy value.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = tmp_path / ".env"
    _ = env_path.write_text(f"OPENAI_API_KEY={_OPENAI_KEY}\n", encoding="utf-8")
    settings_path = tmp_path / "providers.json"
    _ = _write_settings(settings_path, {"openai": {"api_base": _LEGACY_BASE_URL}}).migrate_legacy_endpoints(CredentialLoader(env_path))

    _ = CredentialLoader(env_path).persist_field(provider_ids.OPENAI, CredentialField.API_BASE, "")
    second = ProviderSettingsStore(settings_path).migrate_legacy_endpoints(CredentialLoader(env_path))

    assert second.imported == ()
    assert CredentialLoader(env_path).get_field(provider_ids.OPENAI, CredentialField.API_BASE) is None


def test_legacy_default_ollama_host_is_dropped_without_creating_an_override(tmp_path: Path) -> None:
    """The default Ollama host that old releases always saved is not written to ``.env``.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = tmp_path / ".env"
    settings_path = tmp_path / "providers.json"
    store = _write_settings(settings_path, {"ollama": {"enabled": True, "api_base": "http://localhost:11434"}})

    migration = store.migrate_legacy_endpoints(CredentialLoader(env_path))

    assert migration.imported == ()
    assert not env_path.exists() or "OLLAMA_HOST" not in env_path.read_text(encoding="utf-8")
    assert "api_base" not in _read_settings(settings_path)["ollama"]


def test_failed_env_write_keeps_legacy_field_and_applies_it_for_this_session(tmp_path: Path) -> None:
    """When ``.env`` cannot be written the saved endpoint still applies and is retried later.

    The ``.env`` parent is a regular file, so the real filesystem refuses to
    create the directory the write needs.

    Args:
        tmp_path: Per-test temporary directory.
    """
    blocker = tmp_path / "not-a-directory"
    _ = blocker.write_text("occupied", encoding="utf-8")
    loader = CredentialLoader(blocker / ".env")
    settings_path = tmp_path / "providers.json"
    store = _write_settings(settings_path, {"openrouter": {"enabled": True, "api_base": _LEGACY_BASE_URL}})

    migration = store.migrate_legacy_endpoints(loader)

    assert migration.imported == ()
    assert migration.retained == ("openrouter.api_base",)
    assert loader.get_field(provider_ids.OPENROUTER, CredentialField.API_BASE) == _LEGACY_BASE_URL
    assert _read_settings(settings_path)["openrouter"]["api_base"] == _LEGACY_BASE_URL


@pytest.mark.parametrize(
    ("section", "expected"),
    [
        ({}, None),
        ({"timeout_seconds": 120}, None),
        ({"timeout_seconds": 120, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION}, 120.0),
        ({"timeout_seconds": 45}, 45.0),
        ({"timeout_seconds": 45.5, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION}, 45.5),
        ({"timeout_seconds": None, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION}, None),
        ({"timeout_seconds": True, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION}, None),
        ({"timeout_seconds": 0, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION}, None),
        ({"timeout_seconds": -30, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION}, None),
        ({"timeout_seconds": "90", SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION}, None),
        ({"timeout_seconds": 120, SCHEMA_VERSION_KEY: True}, None),
    ],
    ids=[
        "absent",
        "legacy-untouched-default",
        "versioned-120-is-deliberate",
        "legacy-custom",
        "versioned-fractional",
        "versioned-provider-default",
        "boolean",
        "zero",
        "negative",
        "string",
        "boolean-version-is-not-versioned",
    ],
)
def test_saved_timeout_interpretation(section: dict[str, object], expected: float | None) -> None:
    """Saved timeouts distinguish the legacy untouched default from deliberate choices.

    Args:
        section: A saved provider section.
        expected: The timeout the section must select.
    """
    assert saved_timeout_seconds(section) == expected


def test_coerce_timeout_rejects_non_finite_values() -> None:
    """Infinite and NaN timeouts select the provider default."""
    assert coerce_timeout_seconds(float("inf")) is None
    assert coerce_timeout_seconds(float("nan")) is None
    assert coerce_timeout_seconds(30) == pytest.approx(30.0)


def test_connect_policy_disables_a_provider_either_store_disables(tmp_path: Path) -> None:
    """``providers.json`` and the application configuration can each disable a provider.

    Args:
        tmp_path: Per-test temporary directory.
    """
    store = _write_settings(
        tmp_path / "providers.json",
        {
            "openai": {"enabled": False, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION},
            "grok": {"enabled": True, "timeout_seconds": 75, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION},
            "google": {"enabled": True, "timeout_seconds": 120},
        },
    )
    config = Config()
    config.providers[provider_ids.ANTHROPIC] = ProviderConfig(enabled=False)

    policy = store.connect_policy(config.is_provider_enabled)

    assert policy.disabled == frozenset({provider_ids.OPENAI, provider_ids.ANTHROPIC})
    assert policy.is_enabled(provider_ids.GROK)
    assert policy.timeout_for(provider_ids.GROK) == pytest.approx(75.0)
    assert policy.timeout_for(provider_ids.GOOGLE) is None
    credentials = policy.apply_timeout(provider_ids.GROK, ProviderCredentials(api_key="xai-key", api_base=_ENV_BASE_URL))
    assert credentials.timeout == pytest.approx(75.0)
    assert credentials.api_base == _ENV_BASE_URL


def test_settings_section_excludes_env_owned_fields_and_is_versioned() -> None:
    """The persisted section never carries a key or endpoint and is stamped with the schema version."""
    section = build_settings_section(
        {
            "enabled": False,
            "api_key": _OPENAI_KEY,
            "api_base": _LEGACY_BASE_URL,
            "organization_id": "org-x",
            "timeout_seconds": None,
            "default_model": "gpt-5",
        },
    )

    assert section == {
        "enabled": False,
        "timeout_seconds": None,
        "default_model": "gpt-5",
        SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION,
    }


def test_write_section_preserves_other_providers_and_leaves_no_temporary_files(tmp_path: Path) -> None:
    """Writing one provider's section keeps the others and replaces the file atomically.

    Args:
        tmp_path: Per-test temporary directory.
    """
    settings_path = tmp_path / "config" / "providers.json"
    store = ProviderSettingsStore(settings_path)

    store.write_section("openai", {"enabled": True, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION})
    store.write_section("ollama", {"enabled": False, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION})

    assert _read_settings(settings_path) == {
        "openai": {"enabled": True, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION},
        "ollama": {"enabled": False, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION},
    }
    assert [entry.name for entry in settings_path.parent.iterdir()] == ["providers.json"]
    policy = store.connect_policy()
    assert policy.is_enabled(provider_ids.OLLAMA) is False
    assert policy.is_enabled(provider_ids.GOOGLE) is True


def test_malformed_settings_file_loads_as_empty(tmp_path: Path) -> None:
    """A corrupt ``providers.json`` never blocks startup.

    Args:
        tmp_path: Per-test temporary directory.
    """
    settings_path = tmp_path / "providers.json"
    _ = settings_path.write_text("{ not json", encoding="utf-8")

    store = ProviderSettingsStore(settings_path)

    assert store.load() == {}
    assert store.connect_policy().disabled == frozenset()


def test_session_credentials_keep_keyless_saved_host_and_timeout(tmp_path: Path) -> None:
    """On-demand connects give a keyless provider its saved host and timeout.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = tmp_path / ".env"
    _ = env_path.write_text("OLLAMA_HOST=http://10.9.8.7:11434\n", encoding="utf-8")
    loader = CredentialLoader(env_path)
    store = _write_settings(tmp_path / "providers.json", {"ollama": {"timeout_seconds": 33, SCHEMA_VERSION_KEY: SETTINGS_SCHEMA_VERSION}})

    keyless = resolve_session_credentials(provider_ids.OLLAMA, None, loader=loader, settings=store, api_key_optional=True)
    session_key = "session-supplied-value"
    stored = resolve_session_credentials(
        provider_ids.OLLAMA,
        ProviderCredentials(api_key=session_key, api_base="http://stored-host:11434"),
        loader=loader,
        settings=store,
        api_key_optional=True,
    )

    assert keyless.api_base == "http://10.9.8.7:11434"
    assert keyless.timeout == pytest.approx(33.0)
    assert stored.api_key == session_key
    assert stored.api_base == "http://stored-host:11434"
    assert stored.timeout == pytest.approx(33.0)
