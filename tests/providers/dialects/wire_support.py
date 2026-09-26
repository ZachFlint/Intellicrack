# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared setup for wire-format tests that drive a real ConfigurableProvider.

Every wire test connects a real :class:`ConfigurableProvider` to a
:class:`~tests._helpers.scripted_http_endpoint.ScriptedHttpEndpoint` on the
loopback interface, so the request body goes through the provider's own body
builder and HTTP client and the reply comes back as real bytes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from intellicrack.core.types import ProviderCredentials
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.instances import ProviderInstance


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    from intellicrack.providers.capabilities import ApiDialect, CapabilityOverride
    from tests._helpers.scripted_http_endpoint import ScriptedHttpEndpoint


TEST_API_KEY: Final[str] = "loopback-test-key"
"""API key the provider is connected with; the loopback endpoint accepts any key."""


async def connect_provider(
    endpoint: ScriptedHttpEndpoint,
    dialect: ApiDialect,
    *,
    model: str,
    overrides: Mapping[str, CapabilityOverride] | None = None,
    headers: Mapping[str, str] | None = None,
) -> ConfigurableProvider:
    """Connect a ConfigurableProvider for one dialect to a loopback endpoint.

    Args:
        endpoint: The running loopback endpoint.
        dialect: The wire format the instance speaks.
        model: The instance's default model.
        overrides: Per-model capability overrides.
        headers: Custom request headers configured on the instance.

    Returns:
        ConfigurableProvider: The connected provider.
    """
    instance = ProviderInstance(
        instance_id="loopback-wire",
        dialect=dialect,
        api_base=endpoint.base_url,
        default_model=model,
        headers=dict(headers or {}),
        model_overrides=dict(overrides or {}),
    )
    provider = ConfigurableProvider(instance)
    await provider.connect(ProviderCredentials(api_key=TEST_API_KEY))
    return provider


async def collect(stream: AsyncIterator[str]) -> str:
    """Drain a text stream into one string.

    Args:
        stream: The provider's text stream.

    Returns:
        str: Every chunk, concatenated.
    """
    return "".join([chunk async for chunk in stream])
