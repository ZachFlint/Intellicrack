# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates: a duplicated built-in provider reaches the service it was copied from.

Duplicating a built-in creates an ordinary instance that speaks its dialect
directly through :class:`ConfigurableProvider`, which resolves each dialect's
request and model-list paths relative to the instance's base URL. These gates
fail when a duplicated OpenAI, Anthropic or Google instance has no base URL
(so it cannot connect at all), or when a duplicated Ollama or HuggingFace
instance resolves its paths against a root that does not serve them.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from intellicrack.core.types import ProviderCredentials
from intellicrack.providers import ids as provider_ids
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.dialects import adapter_for
from intellicrack.providers.instances import ProviderInstance
from intellicrack.providers.presets import preset_for


_EXPECTED_CHAT_URLS: dict[str, str] = {
    provider_ids.OPENAI: "https://api.openai.com/v1/chat/completions",
    provider_ids.ANTHROPIC: "https://api.anthropic.com/v1/messages",
    provider_ids.GOOGLE: "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent",
    provider_ids.OLLAMA: "http://localhost:11434/v1/chat/completions",
    provider_ids.HUGGINGFACE: "https://router.huggingface.co/v1/chat/completions",
    provider_ids.OPENROUTER: "https://openrouter.ai/api/v1/chat/completions",
    provider_ids.GROK: "https://api.x.ai/v1/chat/completions",
}

_MODEL_IDS: dict[str, str] = {provider_ids.GOOGLE: "gemini-2.5-pro"}


def _duplicate(provider_id: str) -> ProviderInstance:
    """Materialize a built-in preset as a new instance, as Duplicate does.

    Args:
        provider_id: The built-in to duplicate.

    Returns:
        ProviderInstance: The duplicate.
    """
    preset = preset_for(provider_id)
    assert preset is not None
    return ProviderInstance.from_preset(preset, instance_id=f"{provider_id}-copy")


@pytest.mark.parametrize("provider_id", sorted(_EXPECTED_CHAT_URLS))
def test_duplicate_resolves_the_documented_endpoint(provider_id: str) -> None:
    """The duplicate's base URL plus its dialect's path is the service's documented endpoint.

    Args:
        provider_id: The built-in duplicated.
    """
    instance = _duplicate(provider_id)
    assert instance.api_base is not None, f"duplicated {provider_id} has no base URL"
    path = adapter_for(instance.dialect).endpoint_path(model=_MODEL_IDS.get(provider_id, "model"), stream=False)

    resolved = httpx.URL(instance.api_base.rstrip("/") + "/").join(path)

    assert str(resolved) == _EXPECTED_CHAT_URLS[provider_id]


@pytest.mark.parametrize("provider_id", [provider_ids.OPENAI, provider_ids.ANTHROPIC, provider_ids.GOOGLE])
def test_duplicate_of_an_sdk_default_builtin_connects(provider_id: str) -> None:
    """A duplicate of a built-in whose SDK supplies the base URL can still connect.

    Args:
        provider_id: The built-in duplicated.
    """
    provider = ConfigurableProvider(_duplicate(provider_id))

    async def _run() -> bool:
        try:
            await provider.connect(ProviderCredentials(api_key="sk-duplicate-" + ("d" * 20)))
            return provider.is_connected
        finally:
            await provider.disconnect()

    assert asyncio.run(_run()) is True
