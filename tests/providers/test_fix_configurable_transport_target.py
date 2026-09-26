# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates: the transport policy judges the URL a configurable provider actually connects to.

A saved ``<ID>_API_BASE`` in ``.env`` reaches :meth:`ConfigurableProvider.connect`
as ``credentials.api_base`` and wins over the instance's own base URL. The
plain-HTTP-to-a-public-host rule has to be applied to that URL. These gates
fail when it is applied to the instance's base URL instead, which lets a key
travel over plain HTTP to a public host without acknowledgement, or withholds
a key from an HTTPS endpoint.
"""

from __future__ import annotations

import asyncio

import pytest

from intellicrack.core.types import AuthenticationError, ProviderCredentials
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.instances import ProviderInstance


_KEY = "sk-transport-" + ("t" * 24)
_PUBLIC_PLAINTEXT = "http://gateway.example.com/v1"
_SECURE = "https://gateway.example.com/v1"


def _connect(instance: ProviderInstance, api_base: str) -> ConfigurableProvider:
    """Connect a configurable provider with a base URL override.

    Args:
        instance: The instance to connect.
        api_base: The base URL passed in the connect credentials.

    Returns:
        ConfigurableProvider: The connected provider.
    """
    provider = ConfigurableProvider(instance)

    async def _run() -> None:
        try:
            await provider.connect(ProviderCredentials(api_key=_KEY, api_base=api_base))
        finally:
            await provider.disconnect()

    asyncio.run(_run())
    return provider


def test_key_is_withheld_from_a_public_plaintext_override() -> None:
    """An HTTPS instance whose ``.env`` override is plain HTTP to a public host refuses the key."""
    instance = ProviderInstance(instance_id="my-gw", api_base=_SECURE)

    with pytest.raises(AuthenticationError):
        _ = _connect(instance, _PUBLIC_PLAINTEXT)


def test_acknowledged_public_plaintext_override_connects() -> None:
    """The acknowledgement lets the key travel to the overriding plain-HTTP host."""
    instance = ProviderInstance(instance_id="my-gw", api_base=_SECURE, insecure_transport_acknowledged=True)

    provider = _connect(instance, _PUBLIC_PLAINTEXT)

    assert provider.instance.may_send_api_key(_PUBLIC_PLAINTEXT) is True


def test_secure_override_of_a_plaintext_instance_sends_the_key() -> None:
    """A plain-HTTP instance overridden to HTTPS is judged by the HTTPS URL it really uses."""
    instance = ProviderInstance(instance_id="my-gw", api_base=_PUBLIC_PLAINTEXT)

    provider = _connect(instance, _SECURE)

    assert provider.instance.may_send_api_key(_SECURE) is True
    assert provider.instance.may_send_api_key() is False
