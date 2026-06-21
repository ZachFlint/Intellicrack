# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for provider bug fixes.

Validates that the critical/high bug fixes to the AI provider system work
correctly by driving the real Intellicrack production code end-to-end.  Every
assertion is checked against an independent oracle (the OAuth2 / PKCE spec, the
URL the production builder emits parsed back with ``urllib``, the HuggingFace
503-fallback contract, and the OpenRouter micro-dollar pricing arithmetic
recomputed separately).  No production unit is mocked; doubles appear only at
the external transport boundary (a real ``httpx.Response`` carried by an
exception, exactly as the HuggingFace SDK delivers it).
"""

from __future__ import annotations

import asyncio
import importlib
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import httpx
import pytest

from intellicrack.core.config import Config
from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    AuthenticationError,
    ModelInfo,
    ProviderCredentials,
    ProviderName,
)
from intellicrack.credentials.oauth import (
    OAUTH_CONFIGS,
    OAuthConfig,
    OAuthConfigurationError,
    OAuthManager,
    OAuthProvider,
    verify_pkce_pair,
)
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.huggingface import HuggingFaceProvider
from intellicrack.providers.openrouter import OpenRouterProvider
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.provider_config import CredentialSource, CredentialSourceDetector


if TYPE_CHECKING:
    from collections.abc import Callable


_MICRO_MULTIPLIER = 1_000_000
_FLOAT_TOLERANCE = 1e-6


class _ResponseCarrierError(Exception):
    """Exception carrying a real ``httpx.Response`` like ``HfHubHTTPError``.

    HuggingFace's ``HfHubHTTPError`` exposes the originating HTTP response via a
    ``response`` attribute.  This lightweight carrier reproduces that contract so
    the provider's real ``_extract_503_message`` decoder can be driven against a
    genuine ``httpx.Response`` body without depending on SDK constructor
    internals.
    """

    def __init__(self, response: httpx.Response) -> None:
        """Store the response so the extractor can read its body.

        Args:
            response: The real HTTP response to expose as ``self.response``.
        """
        super().__init__("carrier")
        self.response = response


def _extract_503_message(exc: BaseException) -> str:
    """Invoke the provider's protected ``_extract_503_message`` static method.

    Args:
        exc: Exception to pass to the provider decoder.

    Returns:
        str: The human-readable message the provider derives from the error.
    """
    fn = cast("Callable[[BaseException], str]", vars(HuggingFaceProvider)["_extract_503_message"])
    return fn(exc)


class TestAsyncCacheDiscovery:
    """Fix #1: _init_model_discovery was changed from sync to async."""

    @staticmethod
    def test_init_model_discovery_returns_discovery_and_cache_path(tmp_path: Path) -> None:
        """Verify init_model_discovery awaits to a ModelDiscovery and a cache Path.

        Uses a real ProviderRegistry (no registered providers, so no network
        calls) and a real Config pointed at ``tmp_path``.  Awaiting the coroutine
        is itself the gate that the function survived the sync-to-async migration;
        the returned tuple, the cache filename and the concrete ``ModelDiscovery``
        type are then checked against the discovery module's own class.

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
    def test_build_authorization_url_emits_spec_compliant_pkce_request() -> None:
        """Verify OAuthManager builds a spec-compliant PKCE authorization URL.

        Drives the real ``OAuthManager.build_authorization_url`` (the code the
        OAuth-login flow depends on) with a Google config carrying a concrete
        ``client_id``.  The emitted URL is parsed back with ``urllib`` as an
        independent oracle and validated against RFC 6749 / RFC 7636: the query
        must echo the client_id, request an authorization code, carry the
        generated CSRF state, and supply an S256 PKCE challenge that the returned
        ``code_verifier`` actually hashes to.
        """
        base = OAUTH_CONFIGS[OAuthProvider.GOOGLE]
        config = OAuthConfig(
            provider=OAuthProvider.GOOGLE,
            client_id="test-client-id-1234",
            client_secret=None,
            authorization_url=base.authorization_url,
            token_url=base.token_url,
            scopes=base.scopes,
            use_pkce=True,
            revoke_url=base.revoke_url,
        )

        manager = OAuthManager(credential_store=None)
        auth_url, state = manager.build_authorization_url(config)

        parsed = urllib.parse.urlparse(auth_url)
        params = {key: values[0] for key, values in urllib.parse.parse_qs(parsed.query).items()}

        expected_endpoint = urllib.parse.urlparse(base.authorization_url)
        assert (parsed.scheme, parsed.netloc, parsed.path) == (
            expected_endpoint.scheme,
            expected_endpoint.netloc,
            expected_endpoint.path,
        ), f"Authorization endpoint mismatch in {auth_url!r}"

        assert params["client_id"] == "test-client-id-1234", f"client_id not propagated: {params!r}"
        assert params["response_type"] == "code", f"response_type must request an authorization code: {params!r}"
        assert params["redirect_uri"] == config.redirect_uri, f"redirect_uri mismatch: {params!r}"
        assert params["scope"] == " ".join(config.scopes), f"scope set mismatch: {params!r}"
        assert params["state"] == state.state, "state parameter must match the returned OAuthState"
        assert params["code_challenge_method"] == "S256", f"PKCE method must be S256: {params!r}"

        assert state.code_verifier is not None, "PKCE flow must produce a code_verifier"
        assert verify_pkce_pair(state.code_verifier, params["code_challenge"]), "code_verifier must S256-hash to the emitted code_challenge"

    @staticmethod
    def test_build_authorization_url_rejects_missing_client_id() -> None:
        """Verify build_authorization_url raises when the client_id is empty.

        The OAuth-login flow guards against an unconfigured provider via the
        production ``OAuthConfigurationError`` raised by the URL builder.  A
        Google config with an empty ``client_id`` must surface that error rather
        than emit a credential-less URL.
        """
        base = OAUTH_CONFIGS[OAuthProvider.GOOGLE]
        config = OAuthConfig(
            provider=OAuthProvider.GOOGLE,
            client_id="",
            client_secret=None,
            authorization_url=base.authorization_url,
            token_url=base.token_url,
            scopes=base.scopes,
            use_pkce=True,
            revoke_url=base.revoke_url,
        )
        manager = OAuthManager(credential_store=None)
        with pytest.raises(OAuthConfigurationError):
            manager.build_authorization_url(config)


class TestCredentialSourceDetectorPath:
    """Fix #4: CredentialSourceDetector env path resolution."""

    @staticmethod
    def test_detect_source_classifies_environment_credential(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify the detector classifies a key present in os.environ as ENVIRONMENT.

        Drives the real ``CredentialSourceDetector.detect_source`` end-to-end:
        the detector resolves the provider's environment variable name from its
        ``ENV_VAR_MAPPING`` and compares ``os.environ`` against the supplied key.
        With ``ANTHROPIC_API_KEY`` exported and matching the candidate key, the
        production path-resolution and env-lookup logic must classify the source
        as ENVIRONMENT.

        Args:
            tmp_path: Per-test temporary directory used for the config path.
            monkeypatch: Pytest fixture used to set the environment variable at
                the OS boundary (not the unit under test).
        """
        env_var = CredentialSourceDetector.ENV_VAR_MAPPING.get("anthropic")
        assert env_var is not None, "anthropic must map to an env var in ENV_VAR_MAPPING"

        env_value = "sk-ant-environment-resolution-oracle"
        monkeypatch.setenv(env_var, env_value)

        detector = CredentialSourceDetector(tmp_path / "config.json")
        source = detector.detect_source("anthropic", env_value)

        assert source == CredentialSource.ENVIRONMENT, f"Expected ENVIRONMENT classification, got {source!r}"

    @staticmethod
    def test_detect_source_returns_not_configured_for_empty_key(tmp_path: Path) -> None:
        """Verify the detector reports NOT_CONFIGURED for an empty credential.

        Exercises the real early-return branch in ``detect_source``: an empty key
        must classify as NOT_CONFIGURED regardless of environment or config file
        state.

        Args:
            tmp_path: Per-test temporary directory used for the config path.
        """
        detector = CredentialSourceDetector(tmp_path / "config.json")
        source = detector.detect_source("anthropic", "")
        assert source == CredentialSource.NOT_CONFIGURED, f"Empty key must be NOT_CONFIGURED, got {source!r}"

    @staticmethod
    def test_detect_source_unknown_provider_is_manual(tmp_path: Path) -> None:
        """Verify a provider with no env-var mapping classifies a key as MANUAL.

        A provider id absent from ``ENV_VAR_MAPPING`` cannot be sourced from the
        environment, so a non-empty key must classify as MANUAL by the
        production logic.

        Args:
            tmp_path: Per-test temporary directory used for the config path.
        """
        assert "totally_unknown_provider" not in CredentialSourceDetector.ENV_VAR_MAPPING
        detector = CredentialSourceDetector(tmp_path / "config.json")
        source = detector.detect_source("totally_unknown_provider", "some-key-value")
        assert source == CredentialSource.MANUAL, f"Unmapped provider must be MANUAL, got {source!r}"


class TestHuggingFaceJsonDecode:
    """Fix #5: HuggingFace provider handles malformed JSON responses."""

    @staticmethod
    def test_html_503_body_falls_back_to_loading_message() -> None:
        """Verify the provider falls back when a 503 body is HTML, not JSON.

        Drives the real ``HuggingFaceProvider._extract_503_message`` with a 503
        carrier whose body is HTML.  The provider's own ``response.json()`` call
        raises ``json.JSONDecodeError`` internally and the production handler must
        swallow it and return the spec-defined fallback message rather than
        propagating the decode error.
        """
        resp = httpx.Response(503, text="<html>Error</html>")
        message = _extract_503_message(_ResponseCarrierError(resp))
        assert message == "Model is loading and not yet ready", f"HTML body must fall back, got {message!r}"

    @staticmethod
    def test_malformed_503_body_falls_back_to_loading_message() -> None:
        """Verify the provider falls back when a 503 body is not valid JSON.

        A non-JSON byte body forces the provider's guarded ``response.json()`` to
        raise; the production code must return the generic loading message.
        """
        resp = httpx.Response(503, content=b"not json")
        message = _extract_503_message(_ResponseCarrierError(resp))
        assert message == "Model is loading and not yet ready", f"Malformed body must fall back, got {message!r}"

    @staticmethod
    def test_valid_503_json_body_is_parsed_by_provider() -> None:
        """Verify the provider extracts the error and estimated_time from JSON.

        When the 503 body is valid JSON the provider must read the ``error`` and
        ``estimated_time`` fields and format them.  The expected string is built
        independently from the injected field values.
        """
        resp = httpx.Response(503, json={"error": "Model is loading", "estimated_time": 20.0})
        message = _extract_503_message(_ResponseCarrierError(resp))
        assert message == "Model is loading (estimated_time=20.0s)", f"Provider must format JSON body, got {message!r}"

    @staticmethod
    def test_missing_response_attribute_falls_back() -> None:
        """Verify an exception without a response attribute falls back.

        Exceptions that do not carry an ``httpx.Response`` (any non-HTTP error)
        must produce the generic loading message from the production code.
        """
        message = _extract_503_message(RuntimeError("boom"))
        assert message == "Model is loading and not yet ready", f"No-response error must fall back, got {message!r}"


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


class TestOpenRouterPricingConversion:
    """Fix #7: OpenRouter pricing handles non-numeric strings safely."""

    @staticmethod
    def _build_model_info(model_data: dict[str, Any]) -> ModelInfo:
        """Run the real OpenRouter ``_build_model_info`` against a model record.

        Args:
            model_data: A single OpenRouter ``/models`` ``data[]`` entry.

        Returns:
            ModelInfo: The parsed model metadata the provider produces.
        """
        provider = OpenRouterProvider()
        builder = cast(
            "Callable[[OpenRouterProvider, dict[str, Any]], ModelInfo]",
            vars(OpenRouterProvider)["_build_model_info"],
        )
        return builder(provider, model_data)

    def test_valid_pricing_converts_to_micro_dollars(self) -> None:
        """Verify the provider converts per-token pricing to micro-dollar cost.

        Feeds a real OpenRouter model record with string per-token pricing into
        the production ``_build_model_info`` and checks the resulting
        ``input_cost_per_1m_tokens`` / ``output_cost_per_1m_tokens`` against the
        independently recomputed ``float(value) * 1_000_000`` micro-dollar values.
        """
        model_data: dict[str, Any] = {
            "id": "openrouter/test-model",
            "name": "Test Model",
            "context_length": 8192,
            "pricing": {"prompt": "0.000015", "completion": "0.00003"},
        }
        info = self._build_model_info(model_data)

        expected_input = float("0.000015") * _MICRO_MULTIPLIER
        expected_output = float("0.00003") * _MICRO_MULTIPLIER

        assert info.input_cost_per_1m_tokens is not None, "input cost must be parsed"
        assert info.output_cost_per_1m_tokens is not None, "output cost must be parsed"
        assert abs(info.input_cost_per_1m_tokens - expected_input) < _FLOAT_TOLERANCE, (
            f"input micro-dollar mismatch: {info.input_cost_per_1m_tokens} != {expected_input}"
        )
        assert abs(info.output_cost_per_1m_tokens - expected_output) < _FLOAT_TOLERANCE, (
            f"output micro-dollar mismatch: {info.output_cost_per_1m_tokens} != {expected_output}"
        )

    def test_non_numeric_pricing_is_nullified(self) -> None:
        """Verify the provider nullifies non-numeric and empty pricing strings.

        OpenRouter occasionally reports ``"N/A"`` or empty pricing.  The
        production ``_build_model_info`` must catch the ``ValueError`` from
        ``float()`` and set the cost fields to ``None`` instead of crashing.
        """
        model_data: dict[str, Any] = {
            "id": "openrouter/free-model",
            "name": "Free Model",
            "context_length": 4096,
            "pricing": {"prompt": "N/A", "completion": ""},
        }
        info = self._build_model_info(model_data)

        assert info.input_cost_per_1m_tokens is None, f"'N/A' must nullify input cost, got {info.input_cost_per_1m_tokens!r}"
        assert info.output_cost_per_1m_tokens is None, f"empty string must nullify output cost, got {info.output_cost_per_1m_tokens!r}"

    def test_missing_pricing_leaves_costs_unset(self) -> None:
        """Verify a record with no pricing block yields ``None`` cost fields.

        When the model record omits ``pricing`` entirely the provider must leave
        both cost fields ``None`` (the ``None`` inputs skip conversion).
        """
        model_data: dict[str, Any] = {
            "id": "openrouter/no-pricing",
            "name": "No Pricing",
            "context_length": 2048,
        }
        info = self._build_model_info(model_data)

        assert info.input_cost_per_1m_tokens is None, f"missing pricing must leave input cost None, got {info.input_cost_per_1m_tokens!r}"
        assert info.output_cost_per_1m_tokens is None, f"missing pricing must leave output cost None, got {info.output_cost_per_1m_tokens!r}"

    def test_zero_pricing_converts_to_zero(self) -> None:
        """Verify a free model with ``"0"`` pricing converts to ``0.0``.

        A free model reports ``"0"`` per-token cost; the provider must convert it
        to a numeric ``0.0`` (not ``None``), distinguishing "free" from "unknown".
        """
        model_data: dict[str, Any] = {
            "id": "openrouter/zero-cost",
            "name": "Zero Cost",
            "context_length": 4096,
            "pricing": {"prompt": "0", "completion": "0"},
        }
        info = self._build_model_info(model_data)

        assert info.input_cost_per_1m_tokens is not None, "'0' input must convert to a number, not None"
        assert info.output_cost_per_1m_tokens is not None, "'0' output must convert to a number, not None"
        assert abs(info.input_cost_per_1m_tokens) < _FLOAT_TOLERANCE, f"'0' input must convert to 0.0, got {info.input_cost_per_1m_tokens!r}"
        assert abs(info.output_cost_per_1m_tokens) < _FLOAT_TOLERANCE, f"'0' output must convert to 0.0, got {info.output_cost_per_1m_tokens!r}"

    def test_model_info_provider_is_openrouter(self) -> None:
        """Verify ``_build_model_info`` tags the model as the OpenRouter provider.

        Confirms the parsed ``ModelInfo`` carries ``ProviderName.OPENROUTER`` and
        propagates the model id, proving the conversion runs the real builder
        rather than a stand-in.
        """
        model_data: dict[str, Any] = {
            "id": "openrouter/tagged-model",
            "name": "Tagged",
            "context_length": 4096,
            "pricing": {"prompt": "0.000001", "completion": "0.000002"},
        }
        info = self._build_model_info(model_data)
        assert info.provider is ProviderName.OPENROUTER, f"provider tag mismatch: {info.provider!r}"
        assert info.id == "openrouter/tagged-model", f"model id not propagated: {info.id!r}"
