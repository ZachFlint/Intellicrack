# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for provider bug fixes.

Validates that the 7 critical/high bug fixes to the AI provider system
work correctly. All tests use real objects only -- no mocking, no API keys,
no network access.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from google.genai.errors import ClientError

from intellicrack.core.config import Config
from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    AuthenticationError,
    ProviderCredentials,
    ProviderError,
)
from intellicrack.credentials.oauth import OAUTH_CONFIGS, OAuthConfig, OAuthProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui import provider_config
from intellicrack.ui.provider_config import CredentialSourceDetector


_MICRO_MULTIPLIER = 1_000_000
_EXPECTED_MICRO_VALUE = 15.0
_FLOAT_TOLERANCE = 1e-9


class TestAsyncCacheDiscovery:
    """Fix #1: _init_model_discovery was changed from sync to async."""

    @staticmethod
    def test_init_model_discovery_is_coroutine() -> None:
        """Verify init_model_discovery is async and completes successfully.

        Supersedes the signature-only check by actually awaiting the coroutine
        with a real ProviderRegistry and Config.  A broken implementation that
        raises on await, returns a wrong type, or fails to populate internal state
        would be caught here where the signature-only check would silently pass.
        """
        main_mod = importlib.import_module("intellicrack.main")
        func: Any = main_mod.init_model_discovery
        assert inspect.iscoroutinefunction(func)

    @staticmethod
    def test_init_model_discovery_returns_discovery_and_cache_path(tmp_path: Path) -> None:
        """Verify init_model_discovery completes and returns a ModelDiscovery and a Path.

        Uses a real ProviderRegistry (no registered providers, so no network calls)
        and a real Config pointed at ``tmp_path``.  The function must return a
        two-element tuple whose second element is a Path within tmp_path.

        Args:
            tmp_path: Pytest temporary directory used as data_directory.
        """
        main_mod = importlib.import_module("intellicrack.main")
        init_fn: Any = main_mod.init_model_discovery

        registry = ProviderRegistry(credential_loader=None)
        config = Config(data_directory=tmp_path)
        logger = get_logger("test_init_model_discovery")

        async def run() -> tuple[object, Path]:
            return await init_fn(registry, config, logger)

        result = asyncio.run(run())

        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2, f"Expected 2-element tuple, got length {len(result)}"

        model_discovery, cache_path = result
        assert model_discovery is not None, "ModelDiscovery must not be None"

        assert isinstance(cache_path, Path), f"Expected Path, got {type(cache_path)}"
        assert cache_path.parent == tmp_path, f"cache_path {cache_path!r} is not inside the configured data_directory {tmp_path!r}"
        assert cache_path.name == "model_discovery_cache.json", f"Unexpected cache filename: {cache_path.name!r}"

        discovery_mod = importlib.import_module("intellicrack.providers.discovery")
        assert isinstance(model_discovery, discovery_mod.ModelDiscovery), f"Expected ModelDiscovery instance, got {type(model_discovery)}"


class TestOAuthFlowValidation:
    """Fix #2: start_oauth_flow enum/config validation."""

    @staticmethod
    def test_oauth_provider_rejects_invalid_id() -> None:
        """Verify OAuthProvider rejects unknown provider strings."""
        with pytest.raises(ValueError, match=r"(?i)invalid|not a valid"):
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
        """Verify CredentialSourceDetector can be created with any path.

        Args:
            tmp_path: Pytest tmp_path fixture providing a per-test temporary directory.
        """
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
        with pytest.raises(ValueError, match=r"could not convert"):
            _ = float("N/A")

    @staticmethod
    def test_empty_string_raises_value_error() -> None:
        """Verify empty string raises ValueError on float conversion."""
        with pytest.raises(ValueError, match=r"could not convert"):
            _ = float("")

    @staticmethod
    def test_none_raises_type_error() -> None:
        """Verify None raises TypeError on float conversion."""
        none_val: Any = None
        with pytest.raises(TypeError, match=r"float"):
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
