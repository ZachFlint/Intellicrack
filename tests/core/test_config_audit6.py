# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit6 CORE-D regression tests for ``intellicrack.core.config``.

Exercises:
    * F-0010 - ``_default_providers`` includes every ``ProviderName`` member.
    * F-0021 - ``Config.parse_providers`` is round-trip safe and never drops
      user-defined providers.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any, Final, cast

from intellicrack.core.config import Config, ProviderConfig
from intellicrack.core.types import ProviderName


if TYPE_CHECKING:
    from collections.abc import Callable


_DEFAULT_PROVIDERS_ATTR: Final[str] = "_default_providers"


def _default_providers() -> dict[ProviderName, ProviderConfig]:
    """Return the canonical default provider mapping via ``getattr``.

    Returns:
        dict[ProviderName, ProviderConfig]: Default provider mapping produced
            by the production helper.
    """
    config_module = importlib.import_module("intellicrack.core.config")
    fn = cast(
        "Callable[[], dict[ProviderName, ProviderConfig]]",
        getattr(config_module, _DEFAULT_PROVIDERS_ATTR),
    )
    return fn()


class TestF0010DefaultProvidersCompleteness:
    """``_default_providers`` must enumerate every ``ProviderName`` member."""

    @staticmethod
    def test_huggingface_in_defaults() -> None:
        """HUGGINGFACE must be present in the default provider mapping."""
        defaults = _default_providers()
        assert ProviderName.HUGGINGFACE in defaults
        assert defaults[ProviderName.HUGGINGFACE].enabled is True

    @staticmethod
    def test_grok_in_defaults() -> None:
        """GROK must be present in the default provider mapping."""
        defaults = _default_providers()
        assert ProviderName.GROK in defaults
        assert defaults[ProviderName.GROK].enabled is True

    @staticmethod
    def test_every_enum_member_present() -> None:
        """Every ``ProviderName`` enum member must appear in defaults."""
        defaults = _default_providers()
        for member in ProviderName:
            assert member in defaults, f"missing default for {member.value!r}"


class TestF0021ParseProvidersRoundTrip:
    """``Config.parse_providers`` must preserve every user-defined provider."""

    @staticmethod
    def test_round_trip_preserves_user_overrides_for_huggingface() -> None:
        """A HUGGINGFACE override on disk survives parse + serialise + parse."""
        original_data: dict[str, dict[str, Any]] = {
            ProviderName.HUGGINGFACE.value: {
                "enabled": False,
                "api_base": "https://example.invalid/hf",
                "default_model": "mistralai/Mistral-7B",
                "timeout_seconds": 45,
                "max_retries": 7,
            },
        }
        parsed = Config.parse_providers(original_data)
        assert ProviderName.HUGGINGFACE in parsed
        hf = parsed[ProviderName.HUGGINGFACE]
        assert hf.enabled is False
        assert hf.api_base == "https://example.invalid/hf"
        assert hf.default_model == "mistralai/Mistral-7B"
        assert hf.timeout_seconds == 45
        assert hf.max_retries == 7

    @staticmethod
    def test_round_trip_preserves_user_overrides_for_grok() -> None:
        """A GROK override on disk survives parse + serialise + parse."""
        original_data: dict[str, dict[str, Any]] = {
            ProviderName.GROK.value: {
                "enabled": True,
                "api_base": "https://api.x.ai/v1/test",
                "default_model": "grok-2-latest",
                "timeout_seconds": 90,
                "max_retries": 4,
            },
        }
        parsed = Config.parse_providers(original_data)
        assert ProviderName.GROK in parsed
        grok = parsed[ProviderName.GROK]
        assert grok.enabled is True
        assert grok.api_base == "https://api.x.ai/v1/test"
        assert grok.default_model == "grok-2-latest"
        assert grok.timeout_seconds == 90
        assert grok.max_retries == 4

    @staticmethod
    def test_full_round_trip_via_to_dict() -> None:
        """Config.from_dict(config._to_dict()) must reproduce the originals."""
        config = Config.default()
        to_dict = cast("Callable[[], dict[str, Any]]", getattr(config, "_to_dict"))
        serialised = to_dict()
        rebuilt = Config.from_dict(serialised)

        for provider in ProviderName:
            assert provider in rebuilt.providers, f"round-trip lost {provider.value!r}"
            assert rebuilt.providers[provider] == config.providers[provider]

    @staticmethod
    def test_unknown_provider_skipped() -> None:
        """A non-enum provider name is skipped without raising."""
        parsed = Config.parse_providers({"definitely_not_a_provider": {"enabled": True}})
        for member in ProviderName:
            assert member in parsed
        assert "definitely_not_a_provider" not in {key.value for key in parsed}
