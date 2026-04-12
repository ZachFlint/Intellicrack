# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Unit tests for CredentialLoader.

These tests validate that the CredentialLoader can properly read API keys
from the .env file and validate their format.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.credentials.env_loader import CredentialLoader


if TYPE_CHECKING:
    from pathlib import Path


class TestCredentialLoaderInitialization:
    """Tests for CredentialLoader initialization."""

    @staticmethod
    def test_loader_initializes_with_env_path(
        env_file_path: Path,
    ) -> None:
        """Test CredentialLoader can be initialized with explicit path.

        Args:
            env_file_path: Path to the .env file used for credential loading.
        """
        loader = CredentialLoader(env_path=env_file_path)
        assert loader.env_path == env_file_path

    @staticmethod
    def test_loader_initializes_without_path() -> None:
        """Test CredentialLoader can be initialized without explicit path."""
        loader = CredentialLoader()
        assert loader.env_path is not None

    @staticmethod
    def test_loader_finds_env_file(
        env_file_path: Path,
    ) -> None:
        """Test loader finds .env file when it exists.

        Args:
            env_file_path: Path to the .env file used for credential loading.
        """
        loader = CredentialLoader(env_path=env_file_path)
        assert loader.env_path.exists()


_EXPECTED_TUPLE_LENGTH = 2


class TestCredentialValidation:
    """Tests for credential validation methods."""

    @staticmethod
    def test_validate_credentials_returns_tuple(
        credential_loader: CredentialLoader,
    ) -> None:
        """Test validate_credentials returns (bool, str|None) tuple.

        Args:
            credential_loader: Credential loader fixture.
        """
        for provider in ProviderName:
            result = credential_loader.validate_credentials(provider)
            assert isinstance(result, tuple), f"Expected tuple for {provider}"
            assert len(result) == _EXPECTED_TUPLE_LENGTH, f"Expected 2-tuple for {provider}"
            assert isinstance(result[0], bool), f"Expected bool first element for {provider}"
            assert result[1] is None or isinstance(result[1], str), f"Expected None or str second element for {provider}"

    @staticmethod
    def test_get_credentials_returns_credentials_or_none(
        credential_loader: CredentialLoader,
    ) -> None:
        """Test get_credentials returns ProviderCredentials or None.

        Args:
            credential_loader: Credential loader fixture.
        """
        for provider in ProviderName:
            creds = credential_loader.get_credentials(provider)
            if creds is not None:
                assert isinstance(creds, ProviderCredentials), f"Expected ProviderCredentials for {provider}, got {type(creds)}"


class TestProviderListing:
    """Tests for provider listing methods."""

    @staticmethod
    def test_list_configured_providers_returns_list(
        credential_loader: CredentialLoader,
    ) -> None:
        """Test list_configured_providers returns list of ProviderName.

        Args:
            credential_loader: Credential loader fixture.
        """
        configured = credential_loader.list_configured_providers()
        assert isinstance(configured, list)
        for provider in configured:
            assert isinstance(provider, ProviderName), f"Expected ProviderName, got {type(provider)}"

    @staticmethod
    def test_list_missing_providers_returns_list(
        credential_loader: CredentialLoader,
    ) -> None:
        """Test list_missing_providers returns list of ProviderName.

        Args:
            credential_loader: Credential loader fixture.
        """
        missing = credential_loader.list_missing_providers()
        assert isinstance(missing, list)
        for provider in missing:
            assert isinstance(provider, ProviderName), f"Expected ProviderName, got {type(provider)}"

    @staticmethod
    def test_configured_and_missing_cover_all_providers(
        credential_loader: CredentialLoader,
    ) -> None:
        """Test configured + missing covers all providers.

        Args:
            credential_loader: Credential loader fixture.
        """
        configured = set(credential_loader.list_configured_providers())
        missing = set(credential_loader.list_missing_providers())

        all_providers = set(ProviderName)
        covered = configured.union(missing)

        assert covered == all_providers, (
            f"Configured + missing should cover all providers. Missing from coverage: {all_providers - covered}"
        )


class TestApiKeyFormatValidation:
    """Tests for API key format validation."""

    @staticmethod
    def test_anthropic_key_format_validation(
        credential_loader: CredentialLoader,
        *,
        has_anthropic_key: bool,
    ) -> None:
        """Test Anthropic API key format starts with sk-ant-.

        Args:
            credential_loader: Credential loader fixture.
            has_anthropic_key: Whether an Anthropic API key is configured.
        """
        if not has_anthropic_key:
            pytest.skip("ANTHROPIC_API_KEY not configured")

        creds = credential_loader.get_credentials(ProviderName.ANTHROPIC)
        assert creds is not None, "Expected credentials after validation"
        assert creds.api_key is not None, "Expected api_key to be set"
        assert creds.api_key.startswith("sk-ant-"), f"Anthropic key should start with 'sk-ant-', got prefix: {creds.api_key[:10]}..."

    @staticmethod
    def test_openai_key_format_validation(
        credential_loader: CredentialLoader,
        *,
        has_openai_key: bool,
    ) -> None:
        """Test OpenAI API key format starts with sk-.

        Args:
            credential_loader: Credential loader fixture.
            has_openai_key: Whether an OpenAI API key is configured.
        """
        if not has_openai_key:
            pytest.skip("OPENAI_API_KEY not configured")

        creds = credential_loader.get_credentials(ProviderName.OPENAI)
        assert creds is not None, "Expected credentials after validation"
        assert creds.api_key is not None, "Expected api_key to be set"
        assert creds.api_key.startswith("sk-"), f"OpenAI key should start with 'sk-', got prefix: {creds.api_key[:10]}..."

    @staticmethod
    def test_openrouter_key_format_validation(
        credential_loader: CredentialLoader,
        *,
        has_openrouter_key: bool,
    ) -> None:
        """Test OpenRouter API key format starts with sk-or-.

        Args:
            credential_loader: Credential loader fixture.
            has_openrouter_key: Whether an OpenRouter API key is configured.
        """
        if not has_openrouter_key:
            pytest.skip("OPENROUTER_API_KEY not configured")

        creds = credential_loader.get_credentials(ProviderName.OPENROUTER)
        assert creds is not None, "Expected credentials after validation"
        assert creds.api_key is not None, "Expected api_key to be set"
        assert creds.api_key.startswith("sk-or-"), f"OpenRouter key should start with 'sk-or-', got prefix: {creds.api_key[:10]}..."

    @staticmethod
    def test_google_key_exists_when_configured(
        credential_loader: CredentialLoader,
        *,
        has_google_key: bool,
    ) -> None:
        """Test Google API key is non-empty when configured.

        Args:
            credential_loader: Credential loader fixture.
            has_google_key: Whether a Google API key is configured.
        """
        if not has_google_key:
            pytest.skip("GOOGLE_API_KEY not configured")

        creds = credential_loader.get_credentials(ProviderName.GOOGLE)
        assert creds is not None, "Expected credentials after validation"
        assert creds.api_key is not None, "Expected api_key to be set"
        assert len(creds.api_key) > 0, "Google API key should not be empty"


class TestEnvironmentVariableAccess:
    """Tests for environment variable access methods."""

    @staticmethod
    def test_get_env_var_returns_value_or_default(
        credential_loader: CredentialLoader,
    ) -> None:
        """Test get_env_var returns value if set, default otherwise.

        Args:
            credential_loader: Credential loader fixture.
        """
        result = credential_loader.get_env_var("NONEXISTENT_VAR", "default_value")
        assert result == "default_value"

    @staticmethod
    def test_get_env_var_returns_none_without_default(
        credential_loader: CredentialLoader,
    ) -> None:
        """Test get_env_var returns None if not set and no default.

        Args:
            credential_loader: Credential loader fixture.
        """
        result = credential_loader.get_env_var("NONEXISTENT_VAR")
        assert result is None

    @staticmethod
    def test_set_env_var_updates_value(
        credential_loader: CredentialLoader,
    ) -> None:
        """Test set_env_var updates the environment variable.

        Args:
            credential_loader: Credential loader fixture.
        """
        test_key = "TEST_INTELLICRACK_VAR"
        test_value = "test_value_123"

        credential_loader.set_env_var(test_key, test_value)
        result = credential_loader.get_env_var(test_key)

        assert result == test_value


class TestReload:
    """Tests for credential reload functionality."""

    @staticmethod
    def test_reload_maintains_configured_providers(
        credential_loader: CredentialLoader,
    ) -> None:
        """Test reload() maintains the same configured providers.

        Args:
            credential_loader: Credential loader fixture.
        """
        before = set(credential_loader.list_configured_providers())
        credential_loader.reload()
        after = set(credential_loader.list_configured_providers())

        assert before == after, f"Configured providers changed after reload. Before: {before}, After: {after}"
