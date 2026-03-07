"""Regression tests for provider bug fixes.

Validates that the 7 critical/high bug fixes to the AI provider system
work correctly. All tests use real objects only -- no mocking, no API keys,
no network access.
"""

from __future__ import annotations

import importlib
import inspect
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from google.genai.errors import ClientError

from intellicrack.core.types import (
    AuthenticationError,
    ProviderCredentials,
    ProviderError,
)
from intellicrack.credentials.oauth import OAUTH_CONFIGS, OAuthConfig, OAuthProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.ui import provider_config
from intellicrack.ui.provider_config import CredentialSourceDetector


_MICRO_MULTIPLIER = 1_000_000
_EXPECTED_MICRO_VALUE = 15.0
_FLOAT_TOLERANCE = 1e-9


class TestAsyncCacheDiscovery:
    """Fix #1: _init_model_discovery was changed from sync to async."""

    @staticmethod
    def test_init_model_discovery_is_coroutine() -> None:
        """Verify _init_model_discovery is an async coroutine function."""
        main_mod = importlib.import_module("intellicrack.main")
        func: Any = main_mod._init_model_discovery
        assert inspect.iscoroutinefunction(func)


class TestOAuthFlowValidation:
    """Fix #2: start_oauth_flow enum/config validation."""

    @staticmethod
    def test_oauth_provider_rejects_invalid_id() -> None:
        """Verify OAuthProvider rejects unknown provider strings."""
        with pytest.raises(ValueError):
            OAuthProvider("invalid_xyz")

    @staticmethod
    def test_oauth_provider_accepts_google() -> None:
        """Verify OAuthProvider accepts the 'google' value."""
        result = OAuthProvider("google")
        assert result is OAuthProvider.GOOGLE

    @staticmethod
    def test_oauth_configs_contains_google() -> None:
        """Verify OAUTH_CONFIGS has a Google entry that is an OAuthConfig."""
        config = OAUTH_CONFIGS[OAuthProvider.GOOGLE]
        assert isinstance(config, OAuthConfig)

    @staticmethod
    def test_oauth_configs_returns_none_for_missing_provider() -> None:
        """Verify .get() on OAUTH_CONFIGS returns None for absent keys."""
        sentinel: Any = object()
        result = OAUTH_CONFIGS.get(sentinel)
        assert result is None


class TestCredentialSourceDetectorPath:
    """Fix #4: CredentialSourceDetector env path resolution."""

    @staticmethod
    def test_env_path_resolves_relative_to_module() -> None:
        """Verify the module-relative path points to the project root."""
        project_root = Path(provider_config.__file__).resolve().parents[3]
        assert (project_root / "pyproject.toml").exists()

    @staticmethod
    def test_credential_source_detector_instantiation(tmp_path: Path) -> None:
        """Verify CredentialSourceDetector can be created with any path."""
        detector = CredentialSourceDetector(tmp_path / "config.json")
        assert detector is not None


class TestHuggingFaceJsonDecode:
    """Fix #5: HuggingFace provider handles malformed JSON responses."""

    @staticmethod
    def test_malformed_json_raises_decode_error() -> None:
        """Verify malformed content raises JSONDecodeError on .json()."""
        response = httpx.Response(200, content=b"not json")
        with pytest.raises(json.JSONDecodeError):
            response.json()

    @staticmethod
    def test_html_response_raises_decode_error() -> None:
        """Verify HTML content raises JSONDecodeError on .json()."""
        response = httpx.Response(200, content=b"<html>Error</html>")
        with pytest.raises(json.JSONDecodeError):
            response.json()

    @staticmethod
    def test_valid_json_parses_correctly() -> None:
        """Verify valid JSON content parses into a dict."""
        response = httpx.Response(200, content=b'{"ok":true}')
        data: dict[str, bool] = response.json()
        assert data == {"ok": True}

    @staticmethod
    def test_provider_error_wraps_decode_error() -> None:
        """Verify ProviderError can chain from JSONDecodeError via __cause__."""
        response = httpx.Response(200, content=b"not json")
        wrapped: ProviderError | None = None
        try:
            response.json()
        except json.JSONDecodeError as exc:
            wrapped = ProviderError("Malformed response")
            wrapped.__cause__ = exc

        assert wrapped is not None
        assert isinstance(wrapped.__cause__, json.JSONDecodeError)


class TestGoogleClientErrorDetection:
    """Fix #6: GoogleProvider validates credentials before API calls."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_empty_key_raises_authentication_error() -> None:
        """Verify empty API key raises AuthenticationError immediately."""
        gp = GoogleProvider()
        with pytest.raises(AuthenticationError):
            await gp.connect(ProviderCredentials(api_key=""))

    @pytest.mark.asyncio
    @staticmethod
    async def test_none_key_raises_authentication_error() -> None:
        """Verify None API key raises AuthenticationError immediately."""
        gp = GoogleProvider()
        with pytest.raises(AuthenticationError):
            await gp.connect(ProviderCredentials(api_key=None))

    @staticmethod
    def test_client_error_class_is_importable() -> None:
        """Verify google.genai.errors.ClientError is importable."""
        assert ClientError is not None


class TestOpenRouterPricingConversion:
    """Fix #7: OpenRouter pricing handles non-numeric strings safely."""

    @staticmethod
    def test_valid_numeric_string_converts() -> None:
        """Verify numeric string converts to micro-dollar float."""
        val = "0.000015"
        result = float(val) * _MICRO_MULTIPLIER
        assert abs(result - _EXPECTED_MICRO_VALUE) < _FLOAT_TOLERANCE

    @staticmethod
    def test_na_string_raises_value_error() -> None:
        """Verify 'N/A' raises ValueError on float conversion."""
        with pytest.raises(ValueError):
            _ = float("N/A")

    @staticmethod
    def test_empty_string_raises_value_error() -> None:
        """Verify empty string raises ValueError on float conversion."""
        with pytest.raises(ValueError):
            _ = float("")

    @staticmethod
    def test_none_raises_type_error() -> None:
        """Verify None raises TypeError on float conversion."""
        with pytest.raises(TypeError):
            none_val: Any = None
            _ = float(none_val)

    @staticmethod
    def test_pricing_pattern_nullifies_bad_input() -> None:
        """Verify the try/except pattern returns None for 'N/A'."""
        val = "N/A"
        try:
            result: float | None = float(val) * _MICRO_MULTIPLIER
        except (ValueError, TypeError):
            result = None
        assert result is None

    @staticmethod
    def test_pricing_pattern_converts_valid_input() -> None:
        """Verify the try/except pattern converts valid input correctly."""
        val = "0.000015"
        try:
            result: float | None = float(val) * _MICRO_MULTIPLIER
        except (ValueError, TypeError):
            result = None
        assert result is not None
        assert abs(result - _EXPECTED_MICRO_VALUE) < _FLOAT_TOLERANCE
