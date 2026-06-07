# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Unit tests for CredentialLoader.

These tests validate that the CredentialLoader can properly read API keys
from the .env file and validate their format.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.credentials.env_loader import CredentialLoader


def _make_env_file(content: str) -> Path:
    """Write content to a temporary env file and return its path.

    Args:
        content: Lines to write to the env file.

    Returns:
        Path: Absolute path to the created temporary file.
    """
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".env", delete=False) as fh:
        fh.write(content)
        return Path(fh.name)


def _load_and_validate(env_path: Path, provider: ProviderName) -> tuple[bool, str | None]:
    """Create a CredentialLoader from env_path and validate the given provider.

    Args:
        env_path: Path to the temporary env file.
        provider: Provider to validate.

    Returns:
        tuple[bool, str | None]: Validation result tuple.
    """
    return CredentialLoader(env_path=env_path).validate_credentials(provider)


def _assert_msg_mentions(msg: str | None, expected_prefix: str, provider: ProviderName) -> None:
    """Assert that msg is a non-empty str containing expected_prefix.

    Args:
        msg: The error message returned by validate_credentials.
        expected_prefix: The prefix substring that must appear in msg.
        provider: Provider name used in assertion failure messages.
    """
    assert isinstance(msg, str), f"{provider}: error message must be str, got {type(msg)}"
    assert len(msg) > 0, f"{provider}: error message must be non-empty"
    assert expected_prefix in msg, f"{provider}: error {msg!r} must mention {expected_prefix!r}"


def _assert_invalid_key(provider: ProviderName, env_var: str, bad_key: str, expected_prefix: str) -> None:
    """Assert that a key with the wrong prefix fails validation with a diagnostic message.

    Args:
        provider: The provider to validate.
        env_var: The environment variable name for this provider's key.
        bad_key: A key value that does not have the correct prefix.
        expected_prefix: The prefix that should appear in the error message.
    """
    env_path = _make_env_file(f"{env_var}={bad_key}\n")
    try:
        is_valid, msg = _load_and_validate(env_path, provider)
        assert is_valid is False, f"{provider}: key without prefix {expected_prefix!r} must fail"
        _assert_msg_mentions(msg, expected_prefix, provider)
    finally:
        env_path.unlink()


def _assert_valid_key(provider: ProviderName, env_var: str, valid_key: str) -> None:
    """Assert that a key with the correct prefix validates as (True, None).

    Args:
        provider: The provider to validate.
        env_var: The environment variable name for this provider's key.
        valid_key: A key value that has the correct format prefix.
    """
    env_path = _make_env_file(f"{env_var}={valid_key}\n")
    try:
        loader = CredentialLoader(env_path=env_path)
        is_valid, msg = loader.validate_credentials(provider)
        assert is_valid is True, f"{provider}: key {valid_key[:20]}... must pass validation, got ({is_valid}, {msg!r})"
        assert msg is None, f"{provider}: error message must be None on success, got {msg!r}"
    finally:
        env_path.unlink()


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
        """Test validate_credentials returns (bool, str|None) tuple with consistent semantics.

        Asserts the actual validation logic: True iff the key exists and passes
        format checks; when True the error message is None; when False the error
        message is a non-empty diagnostic string.

        Args:
            credential_loader: Credential loader fixture.
        """
        for provider in ProviderName:
            result = credential_loader.validate_credentials(provider)
            assert isinstance(result, tuple), f"Expected tuple for {provider}"
            assert len(result) == _EXPECTED_TUPLE_LENGTH, f"Expected 2-tuple for {provider}"
            assert isinstance(result[0], bool), f"Expected bool first element for {provider}"
            assert result[1] is None or isinstance(result[1], str), f"Expected None or str second element for {provider}"
            if result[0] is True:
                assert result[1] is None, f"When validation succeeds for {provider}, error message must be None, got {result[1]!r}"
            else:
                assert isinstance(result[1], str), f"When validation fails for {provider}, error message must be str, got {result[1]!r}"
                assert len(result[1]) > 0, f"When validation fails for {provider}, error message must be non-empty"

    @staticmethod
    def test_validate_credentials_invalid_key_returns_false_with_message() -> None:
        """Invalid API key formats produce (False, diagnostic-str) for format-checked providers.

        Uses a controlled env file so the test is unconditional and deterministic.
        Each provider with format validation receives a key with the wrong prefix;
        the validation must return False and a non-empty diagnostic string that
        names the expected prefix.
        """
        cases: list[tuple[ProviderName, str, str, str]] = [
            (ProviderName.ANTHROPIC, "ANTHROPIC_API_KEY", "wrongprefix-key12345", "sk-ant-"),
            (ProviderName.OPENAI, "OPENAI_API_KEY", "wrongprefix-key12345", "sk-"),
            (ProviderName.OPENROUTER, "OPENROUTER_API_KEY", "wrongprefix-key12345", "sk-or-"),
            (ProviderName.GROK, "XAI_API_KEY", "wrongprefix-key12345", "xai-"),
        ]
        for provider, env_var, bad_key, expected_prefix in cases:
            _assert_invalid_key(provider, env_var, bad_key, expected_prefix)

    @staticmethod
    def test_validate_credentials_valid_key_format_returns_true() -> None:
        """A key that matches the required prefix format validates as (True, None).

        Uses a controlled env file with a syntactically valid (but fake) key so
        the test is unconditional and independent of live credentials.
        """
        cases: list[tuple[ProviderName, str, str]] = [
            (ProviderName.ANTHROPIC, "ANTHROPIC_API_KEY", "sk-ant-" + "a" * 50),
            (ProviderName.OPENAI, "OPENAI_API_KEY", "sk-" + "a" * 48),
            (ProviderName.OPENROUTER, "OPENROUTER_API_KEY", "sk-or-" + "a" * 48),
            (ProviderName.GROK, "XAI_API_KEY", "xai-" + "a" * 50),
            (ProviderName.HUGGINGFACE, "HUGGINGFACE_API_TOKEN", "hf_" + "a" * 30),
        ]
        for provider, env_var, valid_key in cases:
            _assert_valid_key(provider, env_var, valid_key)

    @staticmethod
    def test_validate_credentials_missing_key_returns_false(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Missing API key produces (False, non-empty-str) for every provider.

        Uses an empty env file and clears every provider's API-key variable
        (and aliases) from ``os.environ`` so the loader's documented
        ``os.environ`` fallback cannot satisfy a provider from the ambient
        shell. This makes the "missing key fails" gate unconditional rather
        than dependent on which real keys happen to be exported.

        Args:
            monkeypatch: Pytest monkeypatch fixture used to isolate ``os.environ``.
        """
        for mapping in CredentialLoader.PROVIDER_MAPPINGS.values():
            monkeypatch.delenv(mapping.api_key_var, raising=False)
            for alias in mapping.api_key_aliases:
                monkeypatch.delenv(alias, raising=False)

        env_path = _make_env_file("")
        try:
            loader = CredentialLoader(env_path=env_path)
            for provider in ProviderName:
                is_valid, msg = loader.validate_credentials(provider)
                assert is_valid is False, f"{provider}: missing key must fail validation"
                assert isinstance(msg, str), f"{provider}: error message for missing key must be str, got {msg!r}"
                assert len(msg) > 0, f"{provider}: error message for missing key must be non-empty"
        finally:
            env_path.unlink()

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
    """Tests for API key format validation.

    All unconditional tests use isolated env files with synthetic
    (structurally valid but not live) API keys so they run regardless of
    whether real credentials are configured in the environment.
    """

    @staticmethod
    def test_anthropic_key_correct_prefix_validates() -> None:
        """Anthropic key with correct prefix sk-ant- validates as (True, None).

        Uses a synthetic key injected via a controlled env file; runs
        unconditionally so the format-validation logic is always exercised.
        """
        _assert_valid_key(ProviderName.ANTHROPIC, "ANTHROPIC_API_KEY", "sk-ant-api03-" + "A" * 95)

    @staticmethod
    def test_anthropic_key_wrong_prefix_fails_validation() -> None:
        """Anthropic key with wrong prefix is rejected with a diagnostic message.

        Unconditional: uses a synthetic bad key injected via a controlled env file.
        """
        _assert_invalid_key(
            ProviderName.ANTHROPIC,
            "ANTHROPIC_API_KEY",
            "sk-wrongprefix-" + "A" * 60,
            "sk-ant-",
        )

    @staticmethod
    def test_openai_key_correct_prefix_validates() -> None:
        """OpenAI key with correct prefix sk- validates unconditionally."""
        _assert_valid_key(ProviderName.OPENAI, "OPENAI_API_KEY", "sk-proj-" + "A" * 40)

    @staticmethod
    def test_openrouter_key_correct_prefix_validates() -> None:
        """OpenRouter key with correct prefix sk-or- validates unconditionally."""
        _assert_valid_key(ProviderName.OPENROUTER, "OPENROUTER_API_KEY", "sk-or-v1-" + "A" * 60)

    @staticmethod
    def test_grok_key_correct_prefix_validates() -> None:
        """Grok key with correct prefix xai- validates unconditionally."""
        _assert_valid_key(ProviderName.GROK, "XAI_API_KEY", "xai-" + "A" * 60)

    @staticmethod
    def test_live_anthropic_key_prefix_when_configured(
        credential_loader: CredentialLoader,
        *,
        has_anthropic_key: bool,
    ) -> None:
        """When a real ANTHROPIC_API_KEY is configured it must start with sk-ant-.

        Skipped when the env var is absent; the unconditional format gate is in
        test_anthropic_key_correct_prefix_validates.

        Args:
            credential_loader: Credential loader fixture.
            has_anthropic_key: Whether an Anthropic API key is configured.
        """
        if not has_anthropic_key:
            pytest.skip("ANTHROPIC_API_KEY not configured")

        creds = credential_loader.get_credentials(ProviderName.ANTHROPIC)
        assert creds is not None, "Expected credentials after validation"
        assert creds.api_key is not None, "Expected api_key to be set"
        assert creds.api_key.startswith("sk-ant-"), f"Live Anthropic key must start with 'sk-ant-', got prefix: {creds.api_key[:10]!r}"


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
